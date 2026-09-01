/* Author: Denis Podgurskii */
import { ptk_controller_index } from "../../../controller/index.js"
import { ptk_controller_macro } from "../../../controller/macro.js"
import { ptk_jwtHelper } from "../../../background/utils.js"
import * as rutils from "../js/rutils.js"
import { PRO_UI_VISIBLE } from "./releaseFeatureFlags.js"
import { escapeUiText, renderDataTableText, renderPreformattedJson } from "./safeUiText.js"
import { captureReportEngineSnapshots } from "./report/reportingContract.js"
import {
    assertDashboardMacroScope,
    compileDashboardScanMacro,
    prepareDashboardScanMacro
} from "./dashboardScanMacro.js"
const controller = new ptk_controller_index()
const macro_controller = new ptk_controller_macro()
const jwtHelper = new ptk_jwtHelper()
var tokens = new Array()
var tokenAdded = false

const exportControllerCache = new Map()
let scanCompressionModulePromise = null

async function getExportController(engine) {
    if (exportControllerCache.has(engine)) {
        return exportControllerCache.get(engine)
    }

    let pending
    switch (engine) {
        case 'dast':
            pending = import("../../../controller/dast.js").then(({ ptk_controller_dast }) => new ptk_controller_dast())
            break
        case 'iast':
            pending = import("../../../controller/iast.js").then(({ ptk_controller_iast }) => new ptk_controller_iast())
            break
        case 'sast':
            pending = import("../../../controller/sast.js").then(({ ptk_controller_sast }) => new ptk_controller_sast())
            break
        case 'sca':
            pending = import("../../../controller/sca.js").then(({ ptk_controller_sca }) => new ptk_controller_sca())
            break
        default:
            throw new Error(`unsupported_export_engine:${engine}`)
    }

    exportControllerCache.set(engine, pending)
    return pending
}

let $runCveInput = null
let $runCveCheckboxWrapper = null
let runCveState = false
let $dashboardHtmlLinkDiscoveryInput = null
let $dashboardHtmlLinkDiscoveryCheckboxWrapper = null
let $dashboardHtmlLinkDiscoveryBudget = null
let dashboardActionInProgress = false
const DASHBOARD_DAST_MACRO_STATE = {
    requested: false,
    started: false
}
const DASHBOARD_SCAN_MACRO_IMPORT_STATE = {
    prepared: null,
    fileName: '',
    text: ''
}
const DASHBOARD_SCAN_MACRO_REPLAY_STATE = {
    active: false,
    sessionId: null
}
const DASHBOARD_POLICY_ENGINES = Object.freeze(['dast', 'iast', 'sast'])
const DASHBOARD_POLICY_SELECTORS = Object.freeze({
    dast: '#dast-scan-policy',
    iast: '#iast-scan-policy',
    sast: '#sast-scan-policy'
})
const DASHBOARD_POLICY_BUILTIN_OPTIONS = Object.freeze({
    dast: Object.freeze([
        { value: 'RECON', label: 'Recon (system)' },
        { value: 'ACTIVE', label: 'Active (system)' }
    ]),
    iast: Object.freeze([
        { value: 'default:0', label: 'Default (system)' }
    ]),
    sast: Object.freeze([
        { value: 'default:0', label: 'Default (system)' }
    ])
})
const DASHBOARD_POLICY_DEFAULT_VALUES = Object.freeze({
    dast: 'ACTIVE',
    iast: 'default:0',
    sast: 'default:0'
})
const dashboardPolicyUiValues = {
    dast: DASHBOARD_POLICY_DEFAULT_VALUES.dast,
    iast: DASHBOARD_POLICY_DEFAULT_VALUES.iast,
    sast: DASHBOARD_POLICY_DEFAULT_VALUES.sast
}

function setRunCveState(enabled, { updateUi = true } = {}) {
    runCveState = !!enabled
    if (!updateUi) {
        return
    }
    if ($runCveCheckboxWrapper && $runCveCheckboxWrapper.length && typeof $runCveCheckboxWrapper.checkbox === 'function') {
        const action = runCveState ? 'set checked' : 'set unchecked'
        $runCveCheckboxWrapper.checkbox(action)
    } else if ($runCveInput && $runCveInput.length) {
        $runCveInput.prop('checked', runCveState)
    }
}

function isRunCveEnabled() {
    return !!runCveState
}

function setDashboardDastRecordMacro(enabled, { updateUi = true } = {}) {
    const next = !!enabled
    DASHBOARD_DAST_MACRO_STATE.requested = next
    if (!updateUi) return
    const $input = $('#dashboard_dast_record_macro')
    const $wrapper = $input.closest('.ui.checkbox')
    if ($wrapper.length && typeof $wrapper.checkbox === 'function') {
        $wrapper.checkbox(next ? 'set checked' : 'set unchecked')
        return
    }
    $input.prop('checked', next)
}

function isDashboardDastRecordMacroEnabled() {
    return $('#dashboard_dast_record_macro').is(':checked')
}

function normalizeDashboardHtmlLinkDiscoveryBudget(value) {
    const normalized = String(value || 'safe').trim().toLowerCase()
    return ['strict', 'safe', 'wide'].includes(normalized) ? normalized : 'safe'
}

function setDashboardHtmlLinkDiscoveryBudget(value) {
    const normalized = normalizeDashboardHtmlLinkDiscoveryBudget(value)
    if ($dashboardHtmlLinkDiscoveryBudget && $dashboardHtmlLinkDiscoveryBudget.length) {
        $dashboardHtmlLinkDiscoveryBudget.val(normalized)
    }
    return normalized
}

function isDashboardHtmlLinkDiscoveryEnabled() {
    return $('#dashboard_dast_autodiscover_links').is(':checked')
}

function syncDashboardHtmlLinkDiscoveryBudgetState(enabled = null) {
    const active = enabled === null ? isDashboardHtmlLinkDiscoveryEnabled() : !!enabled
    if ($dashboardHtmlLinkDiscoveryBudget && $dashboardHtmlLinkDiscoveryBudget.length) {
        $dashboardHtmlLinkDiscoveryBudget.prop('disabled', !active)
        $dashboardHtmlLinkDiscoveryBudget.toggleClass('disabled', !active)
        $dashboardHtmlLinkDiscoveryBudget.closest('.ui.dropdown').toggleClass('disabled', !active)
    }
}

function setDashboardHtmlLinkDiscoveryEnabled(enabled, { updateUi = true } = {}) {
    const next = !!enabled
    if (updateUi) {
        if ($dashboardHtmlLinkDiscoveryCheckboxWrapper && $dashboardHtmlLinkDiscoveryCheckboxWrapper.length && typeof $dashboardHtmlLinkDiscoveryCheckboxWrapper.checkbox === 'function') {
            $dashboardHtmlLinkDiscoveryCheckboxWrapper.checkbox(next ? 'set checked' : 'set unchecked')
        } else if ($dashboardHtmlLinkDiscoveryInput && $dashboardHtmlLinkDiscoveryInput.length) {
            $dashboardHtmlLinkDiscoveryInput.prop('checked', next)
        }
    }
    syncDashboardHtmlLinkDiscoveryBudgetState(next)
}

function getDashboardHtmlLinkDiscoveryBudget() {
    return normalizeDashboardHtmlLinkDiscoveryBudget($dashboardHtmlLinkDiscoveryBudget?.val())
}

async function startDashboardDastMacroRecording(activeTab = null) {
    if (!DASHBOARD_DAST_MACRO_STATE.requested || DASHBOARD_DAST_MACRO_STATE.started) {
        return { success: true, skipped: true }
    }
    const startUrl = activeTab?.url || controller?.activeTab?.url || window.location.href
    const recordingResult = await macro_controller.start(false, startUrl, {
        skipNavigation: true,
        source: 'dashboard_manage_scans'
    })
    if (recordingResult?.success === false) {
        DASHBOARD_DAST_MACRO_STATE.requested = false
        setDashboardDastRecordMacro(false)
        return recordingResult
    }
    DASHBOARD_DAST_MACRO_STATE.started = true
    return recordingResult
}

async function stopDashboardDastMacroRecording(reason = 'dashboard_manage_scans_stopped') {
    if (!DASHBOARD_DAST_MACRO_STATE.started) {
        DASHBOARD_DAST_MACRO_STATE.requested = false
        setDashboardDastRecordMacro(false)
        return null
    }
    try {
        return await macro_controller.stop({ reason })
    } catch (_) {
        return null
    } finally {
        DASHBOARD_DAST_MACRO_STATE.requested = false
        DASHBOARD_DAST_MACRO_STATE.started = false
        setDashboardDastRecordMacro(false)
    }
}

function setDashboardScanMacroStatus(message = '', type = 'info') {
    const $status = $('#dashboard_scan_macro_status')
    $status.removeClass('error success info warning positive negative')
    if (!message) {
        $status.text('').hide()
        return
    }
    const normalized = ['error', 'success', 'warning'].includes(type) ? type : 'info'
    $status.addClass(normalized).text(message).show()
}

function populateDashboardScanMacroFormats() {
    const $select = $('#dashboard_scan_macro_format')
    if (!$select.length || $select.data('ptk-formats-ready')) return
    macro_controller.formats()
        .filter((entry) => entry.canImport)
        .forEach((entry) => {
            $('<option>').val(entry.id).text(entry.label).appendTo($select)
        })
    $select.data('ptk-formats-ready', true)
}

function renderDashboardScanMacroRuntimeFields(prepared) {
    const $container = $('#dashboard_scan_macro_runtime_fields')
    $container.empty().hide()
    const fields = Array.isArray(prepared?.runtimeFields)
        ? prepared.runtimeFields.filter((entry) => !entry.suppliedByImport)
        : []
    if (!fields.length) return
    for (const entry of fields) {
        const safeName = String(entry.name || '')
        const $field = $('<div>').addClass('eight wide field')
        $('<label>').attr('for', `dashboard_scan_macro_value_${safeName}`).text(
            entry.secret ? `${safeName} (secret)` : safeName
        ).appendTo($field)
        $('<input>')
            .attr({
                id: `dashboard_scan_macro_value_${safeName}`,
                type: entry.secret ? 'password' : 'text',
                autocomplete: 'off',
                'data-ptk-macro-name': safeName,
                'data-ptk-macro-secret': entry.secret ? 'true' : 'false'
            })
            .appendTo($field)
        $field.appendTo($container)
    }
    $container.css('display', 'flex')
}

function updateDashboardScanMacroFileUi(fileName = '') {
    const normalized = String(fileName || '').trim()
    $('#dashboard_scan_macro_filename')
        .text(normalized || 'No macro selected')
        .attr('title', normalized)
    $('#dashboard_scan_macro_clear')
        .prop('disabled', !normalized)
        .toggleClass('disabled', !normalized)
}

function clearDashboardScanMacroSelection() {
    DASHBOARD_SCAN_MACRO_IMPORT_STATE.prepared = null
    DASHBOARD_SCAN_MACRO_IMPORT_STATE.fileName = ''
    DASHBOARD_SCAN_MACRO_IMPORT_STATE.text = ''
    $('#dashboard_scan_macro_file').val('')
    $('#dashboard_scan_macro_format').val('auto')
    $('#dashboard_scan_macro_runtime_fields').empty().hide()
    updateDashboardScanMacroFileUi()
    setDashboardScanMacroStatus()
}

function dashboardScanMacroRuntimeValues() {
    const secrets = Object.create(null)
    const variables = Object.create(null)
    $('#dashboard_scan_macro_runtime_fields [data-ptk-macro-name]').each(function () {
        const name = String($(this).attr('data-ptk-macro-name') || '')
        if (!name) return
        const value = String($(this).val() || '')
        if ($(this).attr('data-ptk-macro-secret') === 'true') secrets[name] = value
        else variables[name] = value
    })
    return { secrets, variables }
}

function compileSelectedDashboardScanMacro(activeTab) {
    const prepared = DASHBOARD_SCAN_MACRO_IMPORT_STATE.prepared
    if (!prepared) return null
    assertDashboardMacroScope(prepared.flow, activeTab?.url)
    const runtime = dashboardScanMacroRuntimeValues()
    const compiled = compileDashboardScanMacro(prepared, runtime)
    return { compiled, scopeOrigin: new URL(activeTab.url).origin }
}

async function startDashboardScanMacroReplay(activeTab, selection) {
    if (!selection) return { success: true, skipped: true }
    const result = await macro_controller.replay(
        false,
        selection.compiled.startUrl,
        selection.compiled.events,
        '',
        {
            targetTabId: activeTab.tabId,
            scopeOrigin: selection.scopeOrigin,
            suppressConfirmation: true,
            scanOwned: true,
            source: 'dashboard_manage_scans'
        }
    )
    if (result?.success === false) throw new Error(result?.error || 'macro_replay_start_failed')
    DASHBOARD_SCAN_MACRO_REPLAY_STATE.active = true
    DASHBOARD_SCAN_MACRO_REPLAY_STATE.sessionId = result?.sessionId || null
    return result
}

async function stopDashboardScanMacroReplay(reason = 'dashboard_manage_scans_stopped') {
    if (!DASHBOARD_SCAN_MACRO_REPLAY_STATE.active) return null
    try {
        return await macro_controller.stopReplay({
            reason,
            sessionId: DASHBOARD_SCAN_MACRO_REPLAY_STATE.sessionId
        })
    } catch (_) {
        return null
    } finally {
        DASHBOARD_SCAN_MACRO_REPLAY_STATE.active = false
        DASHBOARD_SCAN_MACRO_REPLAY_STATE.sessionId = null
    }
}

let dashboardExportInProgress = false

async function downloadScanExport(scanController, exportResult, filename, options = {}) {
    if (!exportResult) return false
    if (!scanCompressionModulePromise) {
        scanCompressionModulePromise = import("../js/scanCompression.js")
    }
    const { downloadScanExportResult } = await scanCompressionModulePromise
    return downloadScanExportResult(scanController, exportResult, filename, options)
}

function setDashboardProgressTitle(title = 'Export') {
    const $title = $('#dashboard_export_progress .ptk-export-progress-title')
    if (!$title.length) return
    $title.text(title)
}

function setDashboardExportProgress(percent, message, options = {}) {
    const $progress = $('#dashboard_export_progress')
    const $bar = $('#dashboard_export_progress_bar')
    const $text = $('#dashboard_export_progress_text')
    if (!$progress.length) return
    const safePercent = Math.max(0, Math.min(100, Number(percent) || 0))
    setDashboardProgressTitle(options.title || 'Export')
    $progress.show()
    $bar.css('width', `${safePercent}%`)
    $text.text(message || `Exporting... ${safePercent}%`)
}

function hideDashboardExportProgress(options = {}) {
    const $progress = $('#dashboard_export_progress')
    const $bar = $('#dashboard_export_progress_bar')
    const $text = $('#dashboard_export_progress_text')
    if (!$progress.length) return
    $progress.hide()
    $bar.css('width', '0%')
    setDashboardProgressTitle(options.title || 'Export')
    $text.text(options.message || 'Preparing export...')
}

function buildDashboardChunkProgressHandler(label, engineIndex, engineCount) {
    return function onChunkProgress(event) {
        const phase = String(event?.phase || '')
        const completed = Number(event?.completed || 0)
        const total = Number(event?.total || 0)
        const base = (engineIndex / engineCount) * 100
        const span = 100 / engineCount

        if (phase === 'chunk_start') {
            const msg = total > 1
                ? `${label}: downloading chunks 0/${total}`
                : `${label}: preparing download`
            setDashboardExportProgress(base + Math.min(8, span * 0.08), msg)
            return
        }
        if (phase === 'chunk_download') {
            const enginePercent = total > 0 ? completed / total : 0
            const overall = base + (span * enginePercent)
            setDashboardExportProgress(overall, `${label}: downloading chunks ${completed}/${total}`)
            return
        }
        if (phase === 'done') {
            setDashboardExportProgress(base + span, `${label}: export complete`)
        }
    }
}

function updateManageScanActions(scans) {
    const isRunning = !!(scans?.dast || scans?.iast || scans?.sast || scans?.sca)
    const exportable = scans?.exportable || {}
    const anyExportable = Object.values(exportable).some(Boolean)
    const actionBusy = dashboardActionInProgress || dashboardExportInProgress
    $('#stop_all_scans').toggleClass('disabled', !isRunning || actionBusy)
    $('#export_all_scans').toggleClass('disabled', isRunning || !anyExportable || actionBusy)
    $('#upload_all_scans').toggleClass('disabled', isRunning || !anyExportable || actionBusy)
    $('#run_scan_dlg .confirm_scan_run').toggleClass('disabled', actionBusy)
    $('#run_scan_dlg .dast_scan_stop, #run_scan_dlg .iast_scan_stop, #run_scan_dlg .sast_scan_stop, #run_scan_dlg .sca_scan_stop')
        .toggleClass('disabled', actionBusy)
}

function hideDashboardHelpPopups() {
    const $icons = $('#index_scans_form .question.circle.icon')
    if ($icons.length && typeof $icons.popup === 'function') {
        try {
            $icons.each(function () {
                try {
                    $(this).popup('hide')
                } catch (_) { }
            })
        } catch (_) { }
    }
}

function showDashboardResultModal(header, message, options = {}) {
    hideDashboardHelpPopups()
    const type = String(options?.type || 'error').trim().toLowerCase()
    const allowedTypes = new Set(['error', 'success', 'info', 'warning'])
    const modalType = allowedTypes.has(type) ? type : 'error'
    const $dialog = $('#result_dialog')
    $dialog.removeClass('error success info warning').addClass(modalType)
    $('#result_header').text(header || 'Info')
    $('#result_message').text(message || '')
    $dialog.find('.result_open_settings_btn').toggle(!!options?.showSettings)
    $dialog.modal('show')
}

const $dashboardUploadScansModal = $('#upload_scans_modal')
const $dashboardRunScansModal = $('#run_scan_dlg')
const $dashboardResultDialog = $('#result_dialog')
let $dashboardUploadProjectDropdown = $('#upload_scans_project_select')
const $dashboardUploadScansModalError = $('#upload_scans_modal_error')
const dashboardUploadProjectMap = new Map()
let dashboardPendingUploadResultModal = null
let dashboardUploadModalBusy = false

function resetDashboardModalVisualState($modal) {
    if (!$modal || !$modal.length) return
    $modal.removeClass('loading')
    $modal.find('.ui.dimmer').removeClass('active visible transition fade in').hide()
}

function setDashboardDastAdvancedSettingsExpanded(expanded) {
    const isExpanded = expanded === true
    $('#index_scans_form .ptk-dast-advanced-row, #index_scans_form .ptk-dast-advanced-column')
        .toggleClass('ptk-dast-advanced-visible', isExpanded)
    const $toggle = $('#dashboard_dast_advanced_toggle')
    $toggle.attr('aria-expanded', String(isExpanded))
    $toggle.find('.ptk-dast-advanced-chevron')
        .toggleClass('down', !isExpanded)
        .toggleClass('up', isExpanded)
}

function resetDashboardManageScansModalState() {
    resetDashboardModalVisualState($dashboardRunScansModal)
    setDashboardDastAdvancedSettingsExpanded(false)
    $('#run_scan_dlg > .scrolling.content').scrollTop(0)
    populateDashboardScanMacroFormats()
    clearDashboardScanMacroSelection()
}

function setDashboardUploadModalBusy(busy) {
    dashboardUploadModalBusy = !!busy
    $dashboardUploadScansModal.toggleClass('loading', dashboardUploadModalBusy)
    $dashboardUploadScansModal.find('.actions .approve.button').toggleClass('disabled loading', dashboardUploadModalBusy)
    $dashboardUploadScansModal.find('.actions .cancel.button').toggleClass('disabled', dashboardUploadModalBusy)
    if ($dashboardUploadProjectDropdown && $dashboardUploadProjectDropdown.length) {
        $dashboardUploadProjectDropdown.prop('disabled', dashboardUploadModalBusy)
        $dashboardUploadProjectDropdown.toggleClass('disabled', dashboardUploadModalBusy)
        $dashboardUploadProjectDropdown.closest('.ui.dropdown').toggleClass('disabled', dashboardUploadModalBusy)
    }
}

function resetDashboardUploadModalState({ clearErrors = false } = {}) {
    setDashboardUploadModalBusy(false)
    resetDashboardModalVisualState($dashboardUploadScansModal)
    if (clearErrors) {
        hideDashboardUploadModalError()
    }
}

function resetDashboardResultModalState() {
    resetDashboardModalVisualState($dashboardResultDialog)
}

function applyDashboardReleaseVisibility() {
    $('#run_scan_dlg .ptk-run-scan-intro-actions').toggle(PRO_UI_VISIBLE)
    $('#upload_all_scans').toggle(PRO_UI_VISIBLE)
    setDashboardDastRecordMacro(false)
    $('#dashboard_dast_record_macro').closest('.three.wide.column').toggle(PRO_UI_VISIBLE)
}

function openExtensionSettingsWindow() {
    return browser.windows.create({
        type: 'popup',
        url: browser.runtime.getURL('/ptk/browser/settings.html'),
        width: 1100,
        height: 820
    }).catch(() => null)
}

function countDashboardPolicies(bucket = {}) {
    return Array.isArray(bucket?.metadata) ? bucket.metadata.length : 0
}

function buildDashboardPolicyLoadSuccessMessage(policyState = {}) {
    const dastCount = countDashboardPolicies(policyState?.dast)
    const iastCount = countDashboardPolicies(policyState?.iast)
    const sastCount = countDashboardPolicies(policyState?.sast)
    return `Scan policies loaded.\nDAST: ${dastCount}.\nIAST: ${iastCount}.\nSAST: ${sastCount}.`
}

function buildPolicyLoadErrorMessage(result, scopeLabel = 'scan policies') {
    if (result?.error === 'missing_api_key') {
        return `PTK Pro token is missing. Open Settings -> PTK Pro and add an activation token before loading ${scopeLabel}.`
    }
    const reason = String(result?.message || result?.error || 'unknown_error').trim()
    return `Could not load ${scopeLabel}. Portal returned: ${reason}.`
}

function buildDashboardScanUploadErrorMessage(result, scopeLabel = 'projects') {
    if (result?.error === 'missing_api_key') {
        return `PTK Pro token is missing. Open Settings -> PTK Pro and add an activation token before loading ${scopeLabel}.`
    }
    const reason = String(result?.json?.message || result?.message || result?.error || 'unknown_error').trim()
    return `Could not load ${scopeLabel}. Portal returned: ${reason}.`
}

function isDashboardHandledUploadErrorMessage(message) {
    return /scan already uploaded as\s+"[^"]+"/i.test(String(message || ''))
}

function isDashboardInternalUploadSkipMessage(message) {
    return /scan result is empty/i.test(String(message || ''))
}

function escapeDashboardPolicyHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
}

function syncDashboardPolicyDropdown($select, value) {
    if (!$select || !$select.length) return
    const normalized = value ? String(value) : ''
    $select.val(normalized)
    if (typeof $select.dropdown === 'function') {
        $select.dropdown('refresh')
        $select.dropdown('set selected', normalized)
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

function rebuildDashboardUploadProjectDropdown(projectOptions) {
    let $target = resetSemanticDropdown($dashboardUploadProjectDropdown)
    dashboardUploadProjectMap.clear()
    if (!$target) return
    $target.empty()
    const placeholder = document.createElement('option')
    placeholder.value = ''
    placeholder.textContent = 'Select a project'
    $target.append(placeholder)
    projectOptions.forEach((opt) => {
        const option = document.createElement('option')
        option.value = opt.value
        option.textContent = opt.text
        dashboardUploadProjectMap.set(opt.value, opt.raw)
        $target.append(option)
    })
    $target.dropdown()
    $target.dropdown('clear')
    $dashboardUploadProjectDropdown = $target
}

function hideDashboardUploadModalError() {
    $dashboardUploadScansModalError.hide().text('')
}

function showDashboardUploadModalError(message) {
    $dashboardUploadScansModalError.text(message || '').show()
}

function fetchDashboardPortalProjects() {
    return controller.getProjects().then((result) => {
        if (!result?.success) {
            throw Object.assign(new Error(buildDashboardScanUploadErrorMessage(result, 'projects')), { result })
        }
        const projectOptions = buildProjectOptions(result.json)
        if (!projectOptions.length) {
            throw new Error('No projects available. Create a project in the portal and try again.')
        }
        return projectOptions
    })
}

function normalizeDashboardUploadErrorLine(message) {
    const raw = String(message || '').replace(/\s+/g, ' ').trim()
    if (!raw) return ''
    const withoutProject = raw.replace(/\s+in project\s+"[^"]+"\.?\s*$/i, '')
    return withoutProject.replace(/\.\s*$/, '')
}

function buildDashboardUploadSummaryMessage({ completed = [], skipped = [], errors = [] } = {}) {
    const parts = []
    if (completed.length) {
        parts.push(`Uploaded: ${completed.join(', ')}.`)
    }
    if (skipped.length) {
        parts.push(`Skipped: ${skipped.join(', ')}.`)
    }
    const errorLines = errors
        .map((error) => normalizeDashboardUploadErrorLine(error))
        .filter(Boolean)
    if (errorLines.length) {
        parts.push(errorLines.join('\n'))
    }
    return parts.join('\n') || 'No scans were uploaded.'
}

function getDashboardPolicyDefaultValue(engine) {
    return DASHBOARD_POLICY_DEFAULT_VALUES[String(engine || '').toLowerCase()] || ''
}

function getDashboardPolicyUiValue(engine) {
    const key = String(engine || '').toLowerCase()
    return Object.prototype.hasOwnProperty.call(dashboardPolicyUiValues, key)
        ? String(dashboardPolicyUiValues[key] || '')
        : getDashboardPolicyDefaultValue(key)
}

function setDashboardPolicyUiValue(engine, value) {
    const key = String(engine || '').toLowerCase()
    if (!Object.prototype.hasOwnProperty.call(dashboardPolicyUiValues, key)) return
    const fallback = getDashboardPolicyDefaultValue(key)
    dashboardPolicyUiValues[key] = value === ''
        ? ''
        : String(value || '').trim() || fallback
}

function getDashboardBuiltinPolicyOptions(engine) {
    return DASHBOARD_POLICY_BUILTIN_OPTIONS[String(engine || '').toLowerCase()] || []
}

function buildDashboardPortalOptionValue(entry = {}) {
    const id = String(entry?.id || '').trim()
    return id ? `policy:${id}` : ''
}

function parseDashboardPortalOptionValue(value) {
    const rawValue = String(value || '').trim()
    if (!rawValue.startsWith('policy:')) return null
    const policyId = rawValue.slice('policy:'.length).trim()
    return policyId || null
}

function collectDashboardPortalSelections() {
    const selections = {}
    DASHBOARD_POLICY_ENGINES.forEach((engine) => {
        const $select = $(DASHBOARD_POLICY_SELECTORS[engine])
        if (!$select.length) {
            selections[engine] = null
            return
        }
        const rawValue = String($select.val() || '').trim()
        const policyId = parseDashboardPortalOptionValue(rawValue)
        if (!policyId) {
            selections[engine] = null
            return
        }
        const policyName = String($select.find('option:selected').text() || '').trim() || null
        selections[engine] = {
            policyId,
            policyName
        }
    })
    return selections
}

function buildDashboardPolicyEntries(bucket = {}) {
    const metadata = Array.isArray(bucket?.metadata) ? bucket.metadata.slice() : []
    const selected = bucket?.selectedPolicy && typeof bucket.selectedPolicy === 'object'
        ? bucket.selectedPolicy
        : null
    if (selected?.id && !metadata.some((entry) => String(entry?.id || '') === String(selected.id))) {
        metadata.unshift(selected)
    }
    return metadata.filter((entry) => entry && (entry.id || entry.name))
}

function clearDashboardProPolicyValidation() {
    $('#ptk_pro_policy_validation').hide().text('')
}

function showDashboardPolicyDialog(message, options = {}) {
    clearDashboardProPolicyValidation()
    showDashboardResultModal(
        options?.header || 'Error',
        message || 'Select a scan policy.',
        { type: options?.type || 'error' }
    )
}

function getDashboardPortalErrorMessage(result, fallback = 'unknown_error') {
    if (result?.error === 'missing_api_key') {
        return 'PAT required. Activate the portal token in Settings first.'
    }
    return result?.message || result?.error || fallback
}

function renderDashboardPortalPolicyState(policyState = null) {
    const nextState = (policyState && typeof policyState === 'object') ? policyState : (controller.policyState || {})
    controller.policyState = nextState
    DASHBOARD_POLICY_ENGINES.forEach((engine) => {
        const $select = $(DASHBOARD_POLICY_SELECTORS[engine])
        if (!$select.length) return
        const bucket = nextState?.[engine] || {}
        const entries = buildDashboardPolicyEntries(bucket)
        const hasPortalEntries = entries.length > 0
        const hasSelectedPortalPolicy = !!bucket?.selectedPolicy?.id
        if (!hasPortalEntries && !hasSelectedPortalPolicy) {
            const builtinOptions = getDashboardBuiltinPolicyOptions(engine)
            $select.html(builtinOptions.map((entry) => (
                `<option value="${escapeDashboardPolicyHtml(entry.value)}">${escapeDashboardPolicyHtml(entry.label)}</option>`
            )).join(''))
            syncDashboardPolicyDropdown($select, getDashboardPolicyUiValue(engine) || getDashboardPolicyDefaultValue(engine))
            return
        }

        const options = []
        getDashboardBuiltinPolicyOptions(engine).forEach((entry) => {
            options.push(`<option value="${escapeDashboardPolicyHtml(entry.value)}">${escapeDashboardPolicyHtml(entry.label)}</option>`)
        })
        entries.forEach((entry) => {
            if (!entry?.id) return
            const label = entry.label || entry.name || `Policy #${entry.id}`
            options.push(`<option value="${escapeDashboardPolicyHtml(buildDashboardPortalOptionValue(entry))}">${escapeDashboardPolicyHtml(label)}</option>`)
        })
        $select.html(options.join(''))
        const selectedValue = hasSelectedPortalPolicy
            ? buildDashboardPortalOptionValue(bucket.selectedPolicy)
            : (getDashboardPolicyUiValue(engine) || getDashboardPolicyDefaultValue(engine))
        syncDashboardPolicyDropdown($select, selectedValue)
    })
}

async function clearDashboardLoadedPolicySelections() {
    let latestState = controller.policyState || {}
    for (const engine of DASHBOARD_POLICY_ENGINES) {
        const response = await controller.clearPolicy(engine.toUpperCase()).catch(() => null)
        if (response?.success && response?.policyState) {
            latestState = response.policyState
        }
    }
    return latestState
}

function setDashboardPortalPolicyLoading(loading) {
    const isLoading = !!loading
    $('#load_pro_policies_button')
        .toggleClass('loading', isLoading)
        .toggleClass('disabled', isLoading)
    $('.dashboard-pro-policy-select').prop('disabled', isLoading)
}

function resolveDashboardHelpPopupPosition($icon) {
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

function bindDashboardHelpPopups() {
    $('#index_scans_form .question.circle.icon').each(function () {
        const $icon = $(this)
        let $popup = $icon.closest('.ptk-help-label-row').nextAll('.ptk-help-popup').first()
        if (!$popup.length) {
            $popup = $icon.closest('.field').find('.ptk-help-popup').first()
        }
        if (!$popup.length) return
        if (!String($popup.html() || '').trim()) return
        const existingPopupInstance = $icon.data('module-popup')
        if (existingPopupInstance && typeof existingPopupInstance === 'object') {
            $icon.popup('destroy')
        }
        $icon.popup({
            popup: $popup,
            on: 'hover',
            hoverable: true,
            position: resolveDashboardHelpPopupPosition($icon),
            preserve: true,
            delay: {
                show: 80,
                hide: 120
            }
        })
    })
}

async function refreshDashboardScanState(activeTab = null) {
    const resolvedTab = activeTab || controller.activeTab || (controller.tabId ? { tabId: controller.tabId, url: controller.url } : null)
    const refreshed = await controller.getScans(resolvedTab ? { tabId: resolvedTab.tabId, url: resolvedTab.url } : {})
    applyDashboardScanControls(refreshed?.scans)
    renderDashboardPortalPolicyState(refreshed?.policyState)
    return refreshed
}

function getDashboardCachedActiveTab() {
    if (rutils.isInspectableTabUrl(controller.activeTab?.url) && typeof controller.activeTab?.tabId !== 'undefined') {
        return controller.activeTab
    }
    if (rutils.isInspectableTabUrl(controller.url) && typeof controller.tabId !== 'undefined') {
        return { url: controller.url, tabId: controller.tabId }
    }
    return null
}

function getDashboardCachedScans() {
    const fallbackSettings = {
        maxRequestsPerSecond: 5,
        concurrency: 3,
        dastScanStrategy: 'SMART',
        dastScanPolicy: getDashboardPolicyDefaultValue('dast'),
        dastRecordMacro: false,
        enableHtmlLinkDiscovery: false,
        htmlLinkDiscoveryBudget: 'safe',
        scanControls: { profile: 'safe' }
    }
    const raw = controller.scans && typeof controller.scans === 'object' ? controller.scans : {}
    const exportable = raw.exportable && typeof raw.exportable === 'object' ? raw.exportable : {}
    const dastSettings = raw.dastSettings && typeof raw.dastSettings === 'object' ? raw.dastSettings : {}
    return {
        dast: !!raw.dast,
        iast: !!raw.iast,
        sast: !!raw.sast,
        sca: !!raw.sca,
        hasAnyScanForHost: !!raw.hasAnyScanForHost,
        exportable: {
            dast: !!exportable.dast,
            iast: !!exportable.iast,
            sast: !!exportable.sast,
            sca: !!exportable.sca,
            any: !!exportable.any
        },
        dastSettings: Object.assign({}, fallbackSettings, dastSettings, {
            scanControls: Object.assign({}, fallbackSettings.scanControls, dastSettings.scanControls || {})
        })
    }
}

async function populateManageScansDialog(result = {}, activeTab = null, options = {}) {
    const updateRuntime = options?.updateRuntime === true
    const scans = result?.scans && typeof result.scans === 'object' ? result.scans : getDashboardCachedScans()
    const policyState = result?.policyState && typeof result.policyState === 'object'
        ? result.policyState
        : (controller.policyState || {})
    const resolvedActiveTab = activeTab || getDashboardCachedActiveTab()

    if (!resolvedActiveTab?.url || typeof resolvedActiveTab?.tabId === 'undefined') {
        $('#result_header').text("Error")
        $('#result_message').text("Active tab not set. Reload required tab to activate tracking.")
        $('#result_dialog').modal('show')
        return false
    }

    controller.activeTab = resolvedActiveTab
    controller.tabId = resolvedActiveTab.tabId
    controller.url = resolvedActiveTab.url
    controller.scans = scans
    controller.policyState = policyState

    const host = new URL(resolvedActiveTab.url).host
    $('#scan_host').text(host)
    $('#scan_domains').text(host)
    applyDashboardScanControls(scans)
    renderDashboardPortalPolicyState(policyState)
    clearDashboardProPolicyValidation()

    const settings = scans.dastSettings || getDashboardCachedScans().dastSettings
    $('#maxRequestsPerSecond').val(settings.maxRequestsPerSecond)
    $('#concurrency').val(settings.concurrency)
    $('#dast-scan-strategy').val(settings.dastScanStrategy || 'SMART')
    setDashboardDastRecordMacro(!!settings.dastRecordMacro)
    setDashboardPolicyUiValue('dast', settings.dastScanPolicy || getDashboardPolicyDefaultValue('dast'))
    setDashboardPolicyUiValue('iast', getDashboardPolicyUiValue('iast') || getDashboardPolicyDefaultValue('iast'))
    setDashboardPolicyUiValue('sast', getDashboardPolicyUiValue('sast') || getDashboardPolicyDefaultValue('sast'))
    syncDashboardPolicyDropdown($('#dast-scan-policy'), getDashboardPolicyUiValue('dast'))
    syncDashboardPolicyDropdown($('#iast-scan-policy'), getDashboardPolicyUiValue('iast'))
    syncDashboardPolicyDropdown($('#sast-scan-policy'), getDashboardPolicyUiValue('sast'))
    renderDashboardPortalPolicyState(controller.policyState)
    const dashboardSafetyProfile = (
        settings?.scanControls?.profile ||
        settings?.safetyProfile ||
        'safe'
    )
    $('#dast-safety-profile').val(String(dashboardSafetyProfile).toLowerCase())
    setRunCveState(false)
    setDashboardHtmlLinkDiscoveryBudget('safe')
    setDashboardHtmlLinkDiscoveryEnabled(false)

    const cachedReady = controller._contentReadyByTabId?.[resolvedActiveTab.tabId]
    if (cachedReady === true) {
        setReloadWarning($('#ptk_reload_warning'), false)
        updateRuntimeScanToggles(true)
    } else if (cachedReady === false) {
        setReloadWarning($('#ptk_reload_warning'), true)
        updateRuntimeScanToggles(false)
    } else {
        updateRuntimeScanToggles(false)
    }

    if (updateRuntime) {
        const contentReady = await rutils.pingContentScript(resolvedActiveTab.tabId, { timeoutMs: 1800 })
        setReloadWarning($('#ptk_reload_warning'), !contentReady)
        updateRuntimeScanToggles(contentReady)
    }
    return true
}

async function runDashboardProgressAction({ title, initialMessage, jobs, successMessage, emptyMessage, activeTab = null, trigger = null } = {}) {
    if (dashboardActionInProgress || dashboardExportInProgress) return false
    const queue = Array.isArray(jobs) ? jobs.filter((job) => job && typeof job.run === 'function') : []
    dashboardActionInProgress = true
    if (trigger && trigger.length) {
        trigger.addClass('disabled loading')
    }
    updateManageScanActions(controller.scans)

    setDashboardExportProgress(2, initialMessage || `${title}: preparing...`, { title })

    try {
        if (!queue.length) {
            setDashboardExportProgress(100, emptyMessage || 'No scans selected.', { title })
            const refreshed = await refreshDashboardScanState(activeTab)
            return { refreshed, completed: [], errors: [] }
        }

        const errors = []
        const completed = []
        const skipped = []
        let priorJobFailed = false
        const total = queue.length
        for (let i = 0; i < total; i += 1) {
            const job = queue[i]
            const base = Math.floor((i / total) * 100)
            const done = Math.floor(((i + 1) / total) * 100)
            if (job.requiresAnyPreviousSuccess === true && completed.length === 0) {
                const skipMessage = `${job.label} (no required earlier action succeeded)`
                skipped.push(skipMessage)
                setDashboardExportProgress(done, `${job.label}: skipped`, { title })
                continue
            }
            if (job.requiresPreviousSuccess === true && priorJobFailed) {
                const skipMessage = `${job.label} (a required earlier action failed)`
                skipped.push(skipMessage)
                setDashboardExportProgress(done, `${job.label}: skipped`, { title })
                continue
            }
            setDashboardExportProgress(base, `${job.label}: in progress...`, { title })
            try {
                const result = await Promise.resolve(job.run())
                const outcome = result && typeof result === 'object'
                    ? String(result.__dashboardActionOutcome || '').trim().toLowerCase()
                    : ''
                if (outcome === 'skip') {
                    if (!result?.silent) {
                        const skipMessage = String(result?.message || '').trim()
                        skipped.push(skipMessage ? `${job.label} (${skipMessage})` : job.label)
                    }
                    setDashboardExportProgress(done, `${job.label}: skipped`, { title })
                    continue
                }
                completed.push(job.label)
                setDashboardExportProgress(done, `${job.label}: complete`, { title })
            } catch (err) {
                priorJobFailed = true
                errors.push(`${job.label}: ${err?.message || 'action_failed'}`)
                setDashboardExportProgress(done, `${job.label}: failed`, { title })
            }
        }

        if (errors.length) {
            setDashboardExportProgress(100, `${successMessage || title} complete with ${errors.length} error(s).`, { title })
            const loggableErrors = title === 'Upload'
                ? errors.filter((message) => !isDashboardHandledUploadErrorMessage(message))
                : errors
            if (loggableErrors.length) {
                console.error(`[PTK Dashboard] ${title} errors`, loggableErrors)
            }
        } else {
            setDashboardExportProgress(100, successMessage || `${title} complete.`, { title })
        }

        const refreshed = await refreshDashboardScanState(activeTab)
        return { refreshed, completed, errors, skipped }
    } finally {
        dashboardActionInProgress = false
        if (trigger && trigger.length) {
            trigger.removeClass('loading')
        }
        updateManageScanActions(controller.scans)
        setTimeout(() => {
            if (!dashboardActionInProgress && !dashboardExportInProgress) {
                hideDashboardExportProgress({ title: 'Export', message: 'Preparing export...' })
            }
        }, 1200)
    }
}

function applyDashboardScanControls(scans) {
    if (!scans || typeof scans !== 'object') return
    updateManageScanActions(scans)
    changeScanView({ scans })
    $('#manage_scans').removeClass('disabled')
    updateGenerateReport(scans)
}

function hasDashboardCardData() {
    const tab = controller.tab || {}
    const hasTech = Array.isArray(tab.technologies) && tab.technologies.length > 0
    const hasWaf = Array.isArray(tab.waf) ? tab.waf.length > 0 : !!tab.waf
    const hasCves = Array.isArray(tab.cves) && tab.cves.length > 0
    const hasHeaders = tab.requestHeaders && Object.keys(tab.requestHeaders).length > 0
    const hasOwasp = Array.isArray(tab.findings) && tab.findings.length > 0
    const hasStorage = controller.storage && Object.keys(controller.storage).length > 0
    const hasTabStorage = tab.storage && Object.keys(tab.storage).length > 0
    return hasTech || hasWaf || hasCves || hasHeaders || hasOwasp || hasStorage || hasTabStorage
}

function updateGenerateReport(scans) {
    const hasScan = !!(scans?.hasAnyScanForHost || scans?.exportable?.any)
    const enabled = hasDashboardCardData() || hasScan
    $('#generate_report').toggleClass('disabled', !enabled)
}

function clearDataTable(selector) {
    if (!$.fn.dataTable.isDataTable(selector)) return
    const table = $(selector).DataTable()
    table.clear().draw(false)
}

function resetJwtTokens() {
    tokens.length = 0
    tokenAdded = false
    $('#jwt_btn').hide()
    clearDataTable('#tbl_tokens')
}

function upsertStorageSummaryRow(label, link) {
    if (!$.fn.dataTable.isDataTable('#tbl_storage')) return
    const table = $('#tbl_storage').DataTable()
    const duplicateIndexes = []
    let found = false

    table.rows().every(function (rowIndex) {
        const row = this.data()
        if (!row || row[0] !== label) return
        if (!found) {
            this.data([label, link])
            found = true
            return
        }
        duplicateIndexes.push(rowIndex)
    })

    duplicateIndexes.reverse().forEach((rowIndex) => {
        table.row(rowIndex).remove()
    })

    if (!found) {
        table.row.add([label, link])
    }
    table.draw(false)
}

function resetDashboardCardsForTabChange() {
    controller.tab = {}
    controller.storage = null
    controller.cookies = {}
    controller._headersSig = null
    controller._lastHeadersRequestId = null
    resetJwtTokens()
    clearDataTable('#tbl_technologies')
    clearDataTable('#tbl_cves')
    clearDataTable('#tbl_owasp')
    clearDataTable('#tbl_headers')
    clearDataTable('#tbl_storage')
    clearDataTable('#tbl_cookie')
    $('.loader.owasp').show()
    $('.loader.technologies').show()
    $('.loader.cves').show()
    $('.loader.storage').show()
    updateGenerateReport(controller.scans)
}

function requestTabAnalysisOnce() {
    if (controller._analysisRequested) return
    controller._analysisRequested = true
    controller.requestTabAnalysis(controller.tabId, controller.url).catch(() => {})
}

async function resolveActiveTab(result) {
    if (rutils.isInspectableTabUrl(result?.activeTab?.url) && typeof result?.activeTab?.tabId !== 'undefined') {
        return result.activeTab
    }
    try {
        const tabs = await browser.tabs.query({ currentWindow: true })
        const active = tabs && tabs.length ? tabs.find((tab) => tab.active) : null
        if (rutils.isInspectableTabUrl(active?.url) && typeof active?.id !== 'undefined') {
            return { url: active.url, tabId: active.id }
        }
        if (controller._lastAppTabId) {
            const last = tabs.find((tab) => tab.id === controller._lastAppTabId)
            if (rutils.isInspectableTabUrl(last?.url)) {
                return { url: last.url, tabId: last.id }
            }
        }
        const fallback = tabs.find((tab) => rutils.isInspectableTabUrl(tab?.url))
        if (fallback?.url && typeof fallback?.id !== 'undefined') {
            return { url: fallback.url, tabId: fallback.id }
        }
    } catch (_) { }
    return null
}

function setReloadWarning($el, show) {
    if (!$el || !$el.length) return
    if ($el.is('#ptk_reload_warning') && window._ptkReloadWarningClosed) return
    if (show) $el.show()
    else $el.hide()
}

function updateRuntimeScanToggles(isContentReady) {
    const disabled = !isContentReady
    const $iast = $('#index_scans_form .iast_scan')
    const $sast = $('#index_scans_form .sast_scan')
    $iast.toggleClass('disabled', disabled)
    $iast.find('input').prop('disabled', disabled)
    $sast.toggleClass('disabled', disabled)
    $sast.find('input').prop('disabled', disabled)
}

async function updateDashboardReloadWarning(result) {
    const FALSE_TTL = 5000 // 5 seconds

    if (controller.tabId) {
        const cachedReady = controller._contentReadyByTabId?.[controller.tabId]
        const cachedTime = controller._contentReadyByTabId?.[`${controller.tabId}_time`]

        if (cachedReady === true) {
            setReloadWarning($('#ptk_reload_banner'), false)
            return true
        }

        // Check if cached false has expired
        if (cachedReady === false && cachedTime) {
            if (Date.now() - cachedTime > FALSE_TTL) {
                // TTL expired, clear the cache entry and re-ping
                delete controller._contentReadyByTabId[controller.tabId]
                delete controller._contentReadyByTabId[`${controller.tabId}_time`]
            } else {
                // TTL not expired, show warning
                setReloadWarning($('#ptk_reload_banner'), true)
                return false
            }
        }

        const ready = await rutils.pingContentScript(controller.tabId, { timeoutMs: 750, retries: 1 })
        controller._contentReadyByTabId = controller._contentReadyByTabId || {}
        if (ready) {
            controller._contentReadyByTabId[controller.tabId] = true
            delete controller._contentReadyByTabId[`${controller.tabId}_time`]
            setReloadWarning($('#ptk_reload_banner'), false)
            return true
        } else {
            controller._contentReadyByTabId[controller.tabId] = false
            controller._contentReadyByTabId[`${controller.tabId}_time`] = Date.now()
            setReloadWarning($('#ptk_reload_banner'), true)
            return false
        }
    }
    const activeTab = await resolveActiveTab(result)
    if (!activeTab?.tabId) {
        setReloadWarning($('#ptk_reload_banner'), false)
        return false
    }
    controller.tabId = activeTab.tabId
    if (rutils.isInspectableTabUrl(activeTab.url)) {
        controller._lastAppTabId = activeTab.tabId
        controller._lastAppTabUrl = activeTab.url
    }
    controller._contentReadyByTabId = controller._contentReadyByTabId || {}
    const ready = await rutils.pingContentScript(activeTab.tabId, { timeoutMs: 750, retries: 1 })
    if (ready) {
        controller._contentReadyByTabId[activeTab.tabId] = true
        delete controller._contentReadyByTabId[`${activeTab.tabId}_time`]
    } else {
        controller._contentReadyByTabId[activeTab.tabId] = false
        controller._contentReadyByTabId[`${activeTab.tabId}_time`] = Date.now()
    }
    if (window._ptkReloadBannerClosed) {
        return ready
    }
    setReloadWarning($('#ptk_reload_banner'), !ready)
    return ready
}

function nextHeadersRequestId() {
    const next = (controller._headersRequestCounter || 0) + 1
    controller._headersRequestCounter = next
    return `hdr-${Date.now()}-${next}`
}

function requestHeadersRefresh(tabId) {
    if (!tabId) return
    const requestId = nextHeadersRequestId()
    controller._lastHeadersRequestId = requestId
    controller.tabId = tabId
    browser.runtime.sendMessage({
        channel: "ptk_popup2background_dashboard",
        type: "headers_refresh",
        tabId,
        requestId
    }).catch(() => {})
}

function clearContentTimeout(tabId) {
    if (!tabId || !controller._contentTimeoutByTabId) return
    const handle = controller._contentTimeoutByTabId[tabId]
    if (handle) {
        clearTimeout(handle)
        delete controller._contentTimeoutByTabId[tabId]
    }
}

function scheduleNoAccessFallback(tabId, delayMs = 2500) {
    if (!tabId) return
    controller._contentTimeoutByTabId = controller._contentTimeoutByTabId || {}
    clearContentTimeout(tabId)
    controller._contentTimeoutByTabId[tabId] = setTimeout(() => {
        const ready = controller._contentReadyByTabId?.[tabId]
        if (ready === false) return
        $('.loader.storage').hide()
    }, delayMs)
}


jQuery(function () {
    $('.modal.coupled').modal({
        allowMultiple: true
    })

    $dashboardResultDialog.modal({
        allowMultiple: true,
        onShow: function () {
            resetDashboardResultModalState()
        },
        onHidden: function () {
            resetDashboardResultModalState()
            resetDashboardManageScansModalState()
        }
    })

    $runCveInput = $('#ptk_dast_run_cve')
    $runCveCheckboxWrapper = $runCveInput.closest('.ui.checkbox')
    $dashboardHtmlLinkDiscoveryInput = $('#dashboard_dast_autodiscover_links')
    $dashboardHtmlLinkDiscoveryCheckboxWrapper = $dashboardHtmlLinkDiscoveryInput.closest('.ui.checkbox')
    $dashboardHtmlLinkDiscoveryBudget = $('#dashboard_dast_autodiscovery_budget')
    applyDashboardReleaseVisibility()

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
            const checked = $(this).is(':checked')
            setRunCveState(checked, { updateUi: false })
        })
    }

    if ($dashboardHtmlLinkDiscoveryCheckboxWrapper.length && typeof $dashboardHtmlLinkDiscoveryCheckboxWrapper.checkbox === 'function') {
        $dashboardHtmlLinkDiscoveryCheckboxWrapper.checkbox({
            onChecked() {
                setDashboardHtmlLinkDiscoveryEnabled(true, { updateUi: false })
            },
            onUnchecked() {
                setDashboardHtmlLinkDiscoveryEnabled(false, { updateUi: false })
            }
        })
    }
    if ($dashboardHtmlLinkDiscoveryInput.length) {
        $dashboardHtmlLinkDiscoveryInput.on('change', function () {
            setDashboardHtmlLinkDiscoveryEnabled($(this).is(':checked'), { updateUi: false })
        })
    }
    if ($dashboardHtmlLinkDiscoveryBudget && $dashboardHtmlLinkDiscoveryBudget.length) {
        $dashboardHtmlLinkDiscoveryBudget.on('change', function () {
            setDashboardHtmlLinkDiscoveryBudget($(this).val())
        })
    }

    setRunCveState(false)
    setDashboardHtmlLinkDiscoveryBudget('safe')
    setDashboardHtmlLinkDiscoveryEnabled(false)

    tokens.push = function (item) {
        if (!this.find(e => (e[0] == item[0] && e[1] == item[1] && e[2] == item[2]))) {
            Array.prototype.push.call(this, item)
            this.onPush(item)
        }
    }

    tokens.onPush = function (obj) {
        //console.log(obj)
        $('#jwt_btn').show()
    }
    $('#jwt_btn').on('click', function () {
        controller.save(JSON.parse(JSON.stringify(tokens))).then(function (res) {
            location.href = "./jwt.html?tab=1"
        })

    })

    $('#ptk_reload_banner_close').on('click', function () {
        window._ptkReloadBannerClosed = true
        $('#ptk_reload_banner').hide()
    })

    $('#ptk_reload_warning_close').on('click', function () {
        window._ptkReloadWarningClosed = true
        $('#ptk_reload_warning').hide()
    })


    // Bind Semantic UI tabs only to elements that declare a data-tab (avoid hijacking top nav links).
    $('.menu .item[data-tab]').tab()
    $('#versionInfo').text(browser.runtime.getManifest().version)

    // $("#waf_wrapper").on("click", function () {
    //     $("#waf_wrapper").addClass("fullscreen modal")
    //     $('#waf_wrapper').modal('show')
    // })

    $(document).on("click", ".storage_auth_link", function () {
        let item = this.attributes["data"].textContent
        $(".menu .item").removeClass('active')
        $.tab('change tab', item)
        $("a[data-tab='" + item + "']").addClass('active')
        $('#storage_auth').modal('show')
    })

$(document).on("click", "#generate_report", function () {
        const $button = $(this)
        if ($button.hasClass('loading')) return false
        const openReport = (snapshotId = null) => {
            const query = snapshotId
                ? `?full_report&report_snapshot=${encodeURIComponent(snapshotId)}`
                : '?full_report'
            const url = browser.runtime.getURL(`/ptk/browser/report.html${query}`)
            return browser.windows.create({ type: 'popup', url }).catch(() => {
                return browser.tabs.create({ url })
            })
        }
        const activeTabId = controller.tabId
        const tabHasId = controller.tab && controller.tab.tabId
        const tabMatches = tabHasId ? (controller.tab.tabId === activeTabId) : !!controller.tab
        const tabData = tabMatches ? controller.tab : {}
        const cookies = tabMatches ? (controller.cookies || {}) : {}
        const storage = tabMatches ? (tabData.storage || controller.storage || {}) : {}
        const requestHeaders = tabMatches ? (tabData.requestHeaders || controller.tab?.requestHeaders || {}) : {}
        const findings = tabMatches ? (tabData.findings || controller.tab?.findings || []) : []
        const technologies = tabMatches ? (tabData.technologies || controller.tab?.technologies || []) : []
        const cves = tabMatches ? (tabData.cves || controller.tab?.cves || []) : []
        const waf = tabMatches ? (tabData.waf || controller.tab?.waf || null) : null
        const dashboardSnapshot = {
                "tabId": activeTabId,
                "url": controller.url,
                "technologies": technologies,
                "waf": waf,
                "cves": cves,
                "findings": findings,
                "requestHeaders": requestHeaders,
                "storage": storage,
                "cookies": cookies
            }
        $button.addClass('loading disabled')
        ;(async () => {
            const engineSnapshots = await captureReportEngineSnapshots(getExportController)
            const reportSnapshot = {
                ...dashboardSnapshot,
                engineSnapshots
            }
            const stored = await controller.createReportSnapshot(reportSnapshot)
            if (!stored?.success || !stored?.snapshotId) {
                console.warn('[PTK Report] Unable to create the background-owned report snapshot.', stored?.error || stored)
                await openReport()
                return
            }
            await openReport(stored.snapshotId)
        })().finally(() => {
            $button.removeClass('loading disabled')
        })
        return false

    })


    bindTable('#tbl_cves', { "columns": [{ width: "30%" }, { width: "15%" }, { width: "35%" }, { width: "20%" }] })
    bindTable('#tbl_technologies', { "columns": [{ width: "45%" }, { width: "30%" }, { width: "25%" }] })
    bindTable('#tbl_owasp', { "columns": [{ width: "100%" }] })
    bindTable('#tbl_storage', { "columns": [{ width: "90%" }, { width: "10%", className: 'dt-body-center' }] })

    function handleDashboardInit(result, activeTab) {
            if (result.redirect) {
                location.href = result.redirect
            }
            if (activeTab && !result.activeTab) {
                result.activeTab = activeTab
            }
            controller._lite = !!result.lite
            applyDashboardScanControls(result.scans)
            if (controller.tabId) {
                requestHeadersRefresh(controller.tabId)
            }
            let contentReadyPromise = updateDashboardReloadWarning(result).then((ready) => {
                if (controller.tabId) {
                    scheduleNoAccessFallback(controller.tabId)
                }
                if (ready === false) {
                    $('.loader.technologies').hide()
                    $('.loader.cves').hide()
                }
                return ready
            }).catch(() => false)
            bindInfo()
            if (controller.tab) {
                if (!controller.storage && controller.tab.storage) {
                    controller.storage = controller.tab.storage
                }
                if (Array.isArray(controller.tab.findings) && controller.tab.findings.length) {
                    bindOWASP()
                } else if (!controller._lite) {
                    bindOWASP()
                } else if (!controller.tabId) {
                    $('.loader.owasp').hide()
                }
                if (controller.tab.requestHeaders && Object.keys(controller.tab.requestHeaders).length) {
                    bindHeaders()
                }
                const hasTech = Array.isArray(controller.tab.technologies) && controller.tab.technologies.length
                const hasCves = Array.isArray(controller.tab.cves) && controller.tab.cves.length
                const cacheUpdatedAt = result?.tabCacheUpdatedAt ? Number(result.tabCacheUpdatedAt) : 0
                const cacheStale = cacheUpdatedAt ? (Date.now() - cacheUpdatedAt) > 60000 : true
                if (hasTech) {
                    bindTechnologies()
                }
                if (hasCves) {
                    bindCVEs()
                }
                const needsRefresh = !hasTech || !hasCves || cacheStale
                if (needsRefresh) {
                    contentReadyPromise.then((ready) => {
                        if (ready === false) return
                        $('.loader.technologies').show()
                        $('.loader.cves').show()
                        requestTabAnalysisOnce()
                        window._ptkAnalysisTimeout = setTimeout(() => {
                            $('.loader.technologies').hide()
                            $('.loader.cves').hide()
                        }, 5000)
                    }).catch(() => {})
                } else if (!hasTech) {
                    $('.loader.technologies').hide()
                } else if (!hasCves) {
                    $('.loader.cves').hide()
                }
                if (controller.storage && Object.keys(controller.storage).length) {
                    bindStorage()
                } else {
                    $('.loader.storage').hide()
                    contentReadyPromise.then((ready) => {
                        if (ready === false) return
                        requestTabAnalysisOnce()
                    }).catch(() => {})
                }
            } else if (!controller._lite) {
                bindOWASP()
                // Hide other loaders since there's no tab data
                $('.loader.technologies').hide()
                $('.loader.cves').hide()
                $('.loader.storage').hide()
            } else {
                contentReadyPromise.then((ready) => {
                    if (ready === false) return
                    requestTabAnalysisOnce()
                    window._ptkAnalysisTimeout = setTimeout(() => {
                        $('.loader.technologies').hide()
                        $('.loader.cves').hide()
                    }, 5000)
                }).catch(() => {})
                $('.loader.storage').hide()
                if (!controller.tabId) {
                    $('.loader.owasp').hide()
                }
            }
    }

    resolveActiveTab().then((activeTab) => {
        const initOpts = activeTab?.tabId ? { tabId: activeTab.tabId, url: activeTab.url } : {}
        if (activeTab?.tabId) {
            controller.tabId = activeTab.tabId
            controller.url = activeTab.url
            controller._lastAppTabId = activeTab.tabId
            controller._lastAppTabUrl = activeTab.url
        }
        return controller.init(initOpts).then((result) => handleDashboardInit(result, activeTab))
    }).catch(() => {
        controller.init().then((result) => handleDashboardInit(result, null)).catch(() => {})
    })

    setupCardToggleHandlers()

    rutils.registerDashboardTabListener({
        onTabChange: ({ tabId, url }) => {
            if (controller.tabId === tabId && controller.url === url) return
            resetDashboardCardsForTabChange()
            controller.tabId = tabId
            controller.url = url
            controller._lastAppTabId = tabId
            controller._lastAppTabUrl = url
            controller.init({ tabId, url }).then((result) => handleDashboardInit(result, { tabId, url })).catch(() => {})
        }
    })
})




/* Helpers */


async function bindInfo() {
    if (controller.url) {
        const baseText = controller.url
        $('#dashboard_message_text').text(baseText)
        if (!controller.privacy?.enable_cookie) {
            $('.dropdown.item.notifications').show()
        }
    } else {
        $('#dashboard_message_text').html(dashboardText)
    }
}

async function bindOWASP() {
    let raw = controller.tab?.findings ? controller.tab.findings : new Array()
    let dt = raw.map(item => [item[0]])
    let params = { "data": dt, "columns": [{ width: "100%" }] }
    if ($.fn.dataTable.isDataTable('#tbl_owasp')) {
        $('#tbl_owasp').DataTable().clear().destroy()
        $('#tbl_owasp tbody').remove()
        $('#tbl_owasp').append('<tbody></tbody>')
    }
    let table = bindTable('#tbl_owasp', params)
    table.columns.adjust().draw()
    $('.loader.owasp').hide()
    updateGenerateReport(controller.scans)
}

function bindCookies() {
    if (Object.keys(controller.cookies).length) {
        $("a[data-tab='cookie']").show()
        upsertStorageSummaryRow('Cookie', `<a href="#" class="storage_auth_link" data="cookie">View</a>`)


        let dt = new Array()
        Object.values(controller.cookies).forEach(item => {
            // Object.values(domain).forEach(item => {
            dt.push([item.domain, item.name, item.value, item.httpOnly])
            //})
        })
        dt.sort(function (a, b) {
            if (a[0] === b[0]) { return 0; }
            else { return (a[0] < b[0]) ? -1 : 1; }
        })
        var groupColumn = 0;
        let params = {
            data: dt,
            columnDefs: [
                { "visible": false, "targets": groupColumn },
                { "targets": [0, 1, 2, 3], "render": renderDataTableText }
            ],
            "order": [[groupColumn, 'asc']],
            "drawCallback": function (settings) {
                var api = this.api();
                var rows = api.rows({ page: 'current' }).nodes();
                var last = null;

                api.column(groupColumn, { page: 'current' }).data().each(function (group, i) {
                    if (last !== group) {
                        $(rows).eq(i).before(
                            '<tr class="group" ><td colspan="3"><div class="ui black ribbon label">' + escapeUiText(group) + '</div></td></tr>'
                        );
                        last = group;
                    }
                });
            }
        }

        bindTable('#tbl_cookie', params)

        let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.sessionRegex)
        if (jwtToken) {
            let jwt = JSON.parse(decodedToken)
            tokens.push(['cookie', renderPreformattedJson(jwt["payload"]), jwtToken[1]])
        }
    }
    $('.loader.storage').hide()
    bindTokens()
}

function bindHeaders() {
    if (Object.keys(controller.tab.requestHeaders).length) {
        let dt = new Array()
        Object.keys(controller.tab.requestHeaders).forEach(name => {
            if (name.startsWith('x-') || name == 'authorization' || name == 'cookie') {
                dt.push([name, controller.tab.requestHeaders[name][0]])
            }
        })
        let params = {
            data: dt,
            columnDefs: [{ "targets": [0, 1], "render": renderDataTableText }]
        }

        bindTable('#tbl_headers', params)

        let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.headersRegex)
        if (jwtToken) {
            let jwt = JSON.parse(decodedToken)
            tokens.push(['headers', renderPreformattedJson(jwt["payload"]), jwtToken[1]])
        }
        bindTokens()
        updateGenerateReport(controller.scans)
    }
}

async function bindTechnologies(force = false) {
    let dt = new Array()
    if (controller.tab.technologies)
        Object.values(controller.tab.technologies).forEach(item => {
            dt.push([item.name, item.version, item.category || ''])
        })
    if (!dt.length && !force) {
        return
    }
    const priority = (category) => {
        const value = (category || '').toLowerCase()
        if (value.includes('waf')) {
            return 0
        }
        if (value.includes('security')) {
            return 1
        }
        return 2
    }
    dt.sort((a, b) => {
        const diff = priority(a[2]) - priority(b[2])
        if (diff !== 0) {
            return diff
        }
        return a[0].localeCompare(b[0])
    })
    let params = {
        "data": dt,
        "columns": [
            { width: "45%", render: renderDataTableText },
            { width: "30%", render: renderDataTableText },
            { width: "25%", render: renderDataTableText }
        ]
    }

    bindTable('#tbl_technologies', params)
    $('.loader.technologies').hide()
    updateGenerateReport(controller.scans)
}

async function bindCVEs(force = false) {
    let dt = new Array()
    if (Array.isArray(controller.tab?.cves)) {
        controller.tab.cves.forEach(item => {
            const evidence = item.evidence || {}
            const evidenceText = `H:${evidence.headers || 0} / HTML:${evidence.html || 0} / JS:${evidence.js || 0} / URL:${evidence.url || 0}`
            const verifyText = item.verify?.moduleId ? `DAST module: ${item.verify.moduleId}` : ''
            dt.push([
                item.id || item.title || '',
                item.severity || '',
                evidenceText,
                verifyText
            ])
        })
    }
    if (!dt.length && !force) {
        return
    }
    let params = {
        "data": dt,
        columnDefs: [{ "targets": [0, 1, 2, 3], "render": renderDataTableText }]
    }
    bindTable('#tbl_cves', params)
    $('.loader.cves').hide()
    updateGenerateReport(controller.scans)
}

async function bindTokens(data) {
    if (tokens.length > 0) {
        $('#jwt_btn').show()
        upsertStorageSummaryRow('Tokens', `<a href="#" class="storage_auth_link" data="tokens">View</a>`)
        if (!tokenAdded) {
            tokenAdded = true
        }
        $("a[data-tab='tokens']").show()
        bindTable('#tbl_tokens', { data: tokens })
        controller.save(JSON.parse(JSON.stringify(tokens)))
    } else {
        $('#jwt_btn').hide()
    }
}

function stripPtkStorageKeys(obj) {
    if (!obj || typeof obj !== "object") return obj
    const cleaned = {}
    Object.keys(obj).forEach((key) => {
        if (/^ptk_/i.test(key)) return
        cleaned[key] = obj[key]
    })
    return cleaned
}



function bindStorage(force = false) {
    if (!controller.storage) {
        if (force) {
            $('.loader.storage').hide()
        }
        return
    }
    let dt = new Array()
    Object.keys(controller.storage).forEach(key => {
        let item = JSON.parse(controller.storage[key])
        item = stripPtkStorageKeys(item)
        if (Object.keys(item).length > 0 && item[key] != "") {
            $(document).trigger("bind_" + key, item)
            $("a[data-tab='" + key + "']").show()
            let link = `<a href="#" class="storage_auth_link" data="${key}">View</a>`
            dt.push([key, link])
        }
    })
    // Use Set for O(1) lookup instead of O(n) nested loop
    const table = $('#tbl_storage').DataTable()
    const existingRows = table.rows().data()
    const existingKeys = new Set()
    for (let j = 0; j < existingRows.length; j++) {
        existingKeys.add(existingRows[j][0])
    }

    // Filter to only new rows, then batch add
    const newRows = dt.filter(row => !existingKeys.has(row[0]))
    if (newRows.length > 0) {
        table.rows.add(newRows).draw(false) // false = maintain scroll position
    }
    if (dt.length || force) {
        $('.loader.storage').hide()
    }

    bindTokens()
    updateGenerateReport(controller.scans)
}

$(document).on("bind_localStorage", function (e, item) {
    const filtered = stripPtkStorageKeys(item)
    if (Object.keys(filtered).length > 0) {

        let output = JSON.stringify(filtered, null, 4)
        let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(filtered), jwtHelper.storageRegex)
        if (jwtToken) {
            let jwt = JSON.parse(decodedToken)
            tokens.push(['localStorage', renderPreformattedJson(jwt["payload"]), jwtToken[1]])
        }
        $('#localStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
    }
})

async function loadFullDashboard() {
    const result = await controller.getFullDashboard()
    controller._lite = false
    bindInfo()
    bindOWASP()
    bindHeaders()
    bindTechnologies()
    bindCVEs()
    bindStorage()
    bindCookies()
    return result
}

$(document).on("bind_sessionStorage", function (e, item) {
    const filtered = stripPtkStorageKeys(item)
    if (Object.keys(filtered).length > 0) {
        let output = JSON.stringify(filtered, null, 4)
        let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(filtered), jwtHelper.storageRegex)
        if (jwtToken) {
            let jwt = JSON.parse(decodedToken)
            tokens.push(['sessionStorage', renderPreformattedJson(jwt["payload"]), jwtToken[1]])
        }
        $('#sessionStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
    }
})

function mergeTechnologyRows(entries = []) {
    const dedupe = new Map()

    entries.forEach((entry) => {
        if (!entry || !entry.name) {
            return
        }

        const normalized = {
            name: entry.name,
            version: entry.version || '',
            category: entry.category || ''
        }

        const existing = dedupe.get(normalized.name)
        if (!existing) {
            dedupe.set(normalized.name, normalized)
            return
        }

        if (!existing.version && normalized.version) {
            existing.version = normalized.version
        }

        if (!existing.category && normalized.category) {
            existing.category = normalized.category
        }
    })

    return Array.from(dedupe.values())
}

const cardFullscreenState = {
    current: null
}

function setupCardToggleHandlers() {
    document.addEventListener('click', (event) => {
        const toggle = event.target.closest('.ptk-card-toggle')
        if (!toggle) {
            return
        }
        const card = toggle.closest('.ptk-dashboard-card')
        if (!card) {
            return
        }
        const shouldExpand = !card.classList.contains('ptk-card-fullscreen')
        setCardFullscreen(card, shouldExpand)
    })
}

function setCardFullscreen(card, shouldExpand) {
    if (shouldExpand) {
        if (cardFullscreenState.current && cardFullscreenState.current !== card) {
            cardFullscreenState.current.classList.remove('ptk-card-fullscreen')
            updateCardToggleIcon(cardFullscreenState.current, false)
        }
        card.classList.add('ptk-card-fullscreen')
        document.body.classList.add('ptk-card-fullscreen-active')
        cardFullscreenState.current = card
        card.scrollIntoView({ behavior: 'smooth', block: 'start' })
    } else {
        card.classList.remove('ptk-card-fullscreen')
        document.body.classList.remove('ptk-card-fullscreen-active')
        cardFullscreenState.current = null
    }
    updateCardToggleIcon(card, shouldExpand)
}

function updateCardToggleIcon(card, expanded) {
    const icon = card.querySelector('.ptk-card-toggle i')
    if (!icon) {
        return
    }
    icon.classList.remove(expanded ? 'expand' : 'compress')
    icon.classList.add(expanded ? 'compress' : 'expand')
}


function changeScanView(result) {
    if (result.scans.dast) {
        $('.dast_scan_control').addClass('disable')
        $('.dast_scan_stop').show()
        $('.ui.checkbox.dast_scan').hide()
    } else {
        $('.dast_scan_control').removeClass('disable')
        $('.dast_scan_stop').hide()
        $('.ui.checkbox.dast_scan').show()
    }
    //IAST
    if (result.scans.iast) {
        $('.iast_scan_control').addClass('disable')
        $('.iast_scan_stop').show()
        $('.ui.checkbox.iast_scan').hide()
    } else {
        $('.iast_scan_control').removeClass('disable')
        $('.iast_scan_stop').hide()
        $('.ui.checkbox.iast_scan').show()
    }
    if (result.scans.sast) {
        $('.sast_scan_control').addClass('disable')
        $('.sast_scan_stop').show()
        $('.ui.checkbox.sast_scan').hide()
    } else {
        $('.sast_scan_control').removeClass('disable')
        $('.sast_scan_stop').hide()
        $('.ui.checkbox.sast_scan').show()
    }
    if (result.scans.sca) {
        $('.sca_scan_control').addClass('disable')
        $('.sca_scan_stop').show()
        $('.ui.checkbox.sca_scan').hide()
    } else {
        $('.sca_scan_control').removeClass('disable')
        $('.sca_scan_stop').hide()
        $('.ui.checkbox.sca_scan').show()
    }
}


$(document).on("click", ".dast_scan_stop, .iast_scan_stop, .sast_scan_stop, .sca_scan_stop", function () {
    const $button = $(this)
    if ($button.hasClass('disabled') || dashboardActionInProgress || dashboardExportInProgress) return false
    const activeTab = controller.activeTab || (controller.tabId ? { tabId: controller.tabId, url: controller.url } : null)
    const jobs = []
    if ($button.hasClass('dast_scan_stop')) {
        jobs.push({
            label: 'DAST',
            run: async () => {
                const response = await controller.stopBackgroundScan({ dast: true, iast: false, sast: false, sca: false })
                await stopDashboardDastMacroRecording()
                return response
            }
        })
    }
    if ($button.hasClass('iast_scan_stop')) {
        jobs.push({
            label: 'IAST',
            run: async () => controller.stopBackgroundScan({ dast: false, iast: true, sast: false, sca: false })
        })
    }
    if ($button.hasClass('sast_scan_stop')) {
        jobs.push({
            label: 'SAST',
            run: async () => controller.stopBackgroundScan({ dast: false, iast: false, sast: true, sca: false })
        })
    }
    if ($button.hasClass('sca_scan_stop')) {
        jobs.push({
            label: 'SCA',
            run: async () => controller.stopBackgroundScan({ dast: false, iast: false, sast: false, sca: true })
        })
    }
    runDashboardProgressAction({
        title: 'Stop scans',
        initialMessage: 'Preparing to stop selected scans...',
        jobs,
        successMessage: 'Selected scans stopped.',
        emptyMessage: 'No scans selected to stop.',
        activeTab,
        trigger: $button
    }).catch(() => { })
    return false
})

$(document).on("click", "#stop_all_scans", function () {
    const $button = $(this)
    if ($button.hasClass('disabled') || dashboardActionInProgress || dashboardExportInProgress) return false
    const activeTab = controller.activeTab || (controller.tabId ? { tabId: controller.tabId, url: controller.url } : null)
    const scans = controller.scans || {}
    const jobs = []
    if (DASHBOARD_SCAN_MACRO_REPLAY_STATE.active) {
        jobs.push({
            label: 'Macro replay',
            run: async () => stopDashboardScanMacroReplay()
        })
    }
    const siblingSelection = {
        dast: false,
        iast: !!scans.iast,
        sast: !!scans.sast,
        sca: !!scans.sca
    }
    const siblingLabels = []
    if (siblingSelection.iast) siblingLabels.push('IAST')
    if (siblingSelection.sast) siblingLabels.push('SAST')
    if (siblingSelection.sca) siblingLabels.push('SCA')
    if (siblingLabels.length) {
        jobs.push({
            label: `${siblingLabels.join(' + ')}`,
            run: async () => controller.stopBackgroundScan(siblingSelection)
        })
    }
    if (scans.dast) {
        jobs.push({
            label: 'DAST',
            run: async () => {
                const response = await controller.stopBackgroundScan({ dast: true, iast: false, sast: false, sca: false })
                await stopDashboardDastMacroRecording()
                return response
            }
        })
    }
    runDashboardProgressAction({
        title: 'Stop scans',
        initialMessage: 'Preparing to stop running scans...',
        jobs,
        successMessage: 'All running scans stopped.',
        emptyMessage: 'No running scans to stop.',
        activeTab,
        trigger: $button
    }).catch(() => { })
    return false
})

$(document).on("click", "#export_all_scans", function () {
    const $button = $(this)
    if ($button.hasClass('disabled') || dashboardExportInProgress) return false

    dashboardExportInProgress = true
    $button.addClass('disabled loading')
    setDashboardExportProgress(2, 'Preparing scan exports...')

    ; (async () => {
        const exportJobs = await Promise.all([
            getExportController('dast').then((controller) => ({ label: 'DAST', controller, filename: "PTK_DAST_scan.json" })),
            getExportController('iast').then((controller) => ({ label: 'IAST', controller, filename: "PTK_IAST_scan.json" })),
            getExportController('sast').then((controller) => ({ label: 'SAST', controller, filename: "PTK_SAST_scan.json" })),
            getExportController('sca').then((controller) => ({ label: 'SCA', controller, filename: "PTK_SCA_scan.json" }))
        ])
        const errors = []
        const total = exportJobs.length

        for (let i = 0; i < total; i++) {
            const job = exportJobs[i]
            const base = Math.floor((i / total) * 100)
            setDashboardExportProgress(base, `${job.label}: preparing export payload...`)

            try {
                const exportResult = await job.controller.exportScanResult()
                if (exportResult) {
                    await downloadScanExport(job.controller, exportResult, job.filename, {
                        onProgress: buildDashboardChunkProgressHandler(job.label, i, total)
                    })
                } else {
                    setDashboardExportProgress(
                        Math.floor(((i + 1) / total) * 100),
                        `${job.label}: no data to export`
                    )
                }
            } catch (err) {
                errors.push(`${job.label}: ${err?.message || 'export_failed'}`)
                setDashboardExportProgress(
                    Math.floor(((i + 1) / total) * 100),
                    `${job.label}: export failed`
                )
            }
        }

        if (errors.length > 0) {
            console.error('[PTK Dashboard] Export all scans completed with errors', errors)
            setDashboardExportProgress(100, `Export complete with ${errors.length} error(s).`)
        } else {
            setDashboardExportProgress(100, 'Export complete.')
        }
    })().finally(() => {
        dashboardExportInProgress = false
        $button.removeClass('loading')
        updateManageScanActions(controller.scans)
        setTimeout(() => {
            if (!dashboardExportInProgress) hideDashboardExportProgress()
        }, 1200)
    })

    return false
})

$(document).on("click", "#upload_all_scans", function () {
    if (!PRO_UI_VISIBLE) return false
    if ($(this).hasClass('disabled') || dashboardActionInProgress || dashboardExportInProgress) return false
    hideDashboardUploadModalError()
    dashboardPendingUploadResultModal = null
    resetDashboardUploadModalState({ clearErrors: true })
    const $button = $(this)
    $button.addClass('loading')
    fetchDashboardPortalProjects()
        .then((projectOptions) => {
            rebuildDashboardUploadProjectDropdown(projectOptions)
            $dashboardUploadScansModal
                .modal({
                    allowMultiple: true,
                    onShow: function () {
                        resetDashboardUploadModalState({ clearErrors: true })
                        resetDashboardManageScansModalState()
                    },
                    onHidden: function () {
                        resetDashboardUploadModalState({ clearErrors: true })
                        resetDashboardManageScansModalState()
                        if (dashboardPendingUploadResultModal) {
                            const pending = dashboardPendingUploadResultModal
                            dashboardPendingUploadResultModal = null
                            showDashboardResultModal(pending.header, pending.message, pending.options)
                        }
                    },
                    onApprove: function () {
                        if (dashboardUploadModalBusy || dashboardActionInProgress || dashboardExportInProgress) {
                            return false
                        }
                        const projectId = $dashboardUploadProjectDropdown.val()
                        if (!projectId) {
                            showDashboardUploadModalError('Select a project to continue.')
                            return false
                        }
                        setDashboardUploadModalBusy(true)
                        const payloadProjectId = dashboardUploadProjectMap.get(projectId) ?? projectId
                        const exportable = controller.scans?.exportable || {}
                        const engineLabels = { dast: 'DAST', iast: 'IAST', sast: 'SAST', sca: 'SCA' }
                        const skipped = []
                        const jobs = []
                        const uploadEngines = ['dast', 'iast', 'sast', 'sca']
                        const uploadTask = async () => {
                            for (const engine of uploadEngines) {
                                if (!exportable?.[engine]) {
                                    skipped.push(`${engineLabels[engine]} (no scan data)`)
                                    continue
                                }
                                const scanController = await getExportController(engine)
                                if (typeof scanController?.saveScan !== 'function') {
                                    skipped.push(`${engineLabels[engine]} (upload not supported)`)
                                    continue
                                }
                                jobs.push({
                                    label: engineLabels[engine],
                                    run: async () => {
                                        const response = await scanController.saveScan(payloadProjectId)
                                        if (!response?.success) {
                                            const message = String(response?.json?.message || response?.message || 'upload_failed').trim()
                                            if (isDashboardInternalUploadSkipMessage(message)) {
                                                return { __dashboardActionOutcome: 'skip', silent: true }
                                            }
                                            throw new Error(message || 'upload_failed')
                                        }
                                        return response
                                    }
                                })
                            }
                            const uploadResult = await runDashboardProgressAction({
                                title: 'Upload',
                                initialMessage: 'Preparing selected scans for upload...',
                                jobs,
                                successMessage: 'Scan upload complete.',
                                emptyMessage: 'No scans available to upload.',
                                activeTab: controller.activeTab,
                                trigger: $('#upload_all_scans')
                            })
                            const errors = Array.isArray(uploadResult?.errors) ? uploadResult.errors : []
                            const completed = Array.isArray(uploadResult?.completed) ? uploadResult.completed : []
                            const progressSkipped = Array.isArray(uploadResult?.skipped) ? uploadResult.skipped : []
                            dashboardPendingUploadResultModal = {
                                header: errors.length ? 'Upload complete with errors' : 'Success',
                                message: buildDashboardUploadSummaryMessage({ completed, skipped: skipped.concat(progressSkipped), errors }),
                                options: { type: errors.length ? 'warning' : 'success' }
                            }
                        }
                        uploadTask().catch((err) => {
                            dashboardPendingUploadResultModal = {
                                header: 'Error',
                                message: err?.message || 'Unable to upload scans.',
                                options: { type: 'error' }
                            }
                        }).finally(() => {
                            resetDashboardUploadModalState({ clearErrors: true })
                            resetDashboardManageScansModalState()
                            $dashboardUploadScansModal.modal('hide')
                        })
                        return false
                    }
                })
                .modal('show')
        })
        .catch((err) => {
            const result = err?.result || null
            showDashboardResultModal(
                'Error',
                err?.message || buildDashboardScanUploadErrorMessage(result, 'projects'),
                { type: 'error', showSettings: result?.error === 'missing_api_key' }
            )
        })
        .finally(() => {
            $button.removeClass('loading')
        })
    return false
})

async function prepareSelectedDashboardScanMacro() {
    if (!DASHBOARD_SCAN_MACRO_IMPORT_STATE.text) {
        clearDashboardScanMacroSelection()
        return null
    }
    const activeTab = controller.activeTab || getDashboardCachedActiveTab()
    if (!activeTab?.url) throw new Error('The active scan tab is unavailable.')
    const prepared = prepareDashboardScanMacro(DASHBOARD_SCAN_MACRO_IMPORT_STATE.text, {
        fileName: DASHBOARD_SCAN_MACRO_IMPORT_STATE.fileName,
        format: $('#dashboard_scan_macro_format').val() || 'auto',
        targetUrl: activeTab.url
    })
    DASHBOARD_SCAN_MACRO_IMPORT_STATE.prepared = prepared
    renderDashboardScanMacroRuntimeFields(prepared)
    const warnings = prepared.diagnostics.filter((entry) => entry.level === 'warning').length
    const suffix = warnings ? ` ${warnings} conversion warning(s) will be preserved for review.` : ''
    setDashboardScanMacroStatus(
        `${prepared.formatLabel}: ${prepared.flow.steps.length} step(s) ready for exact-origin replay.${suffix}`,
        warnings ? 'warning' : 'success'
    )
    return prepared
}

$(document).on('change', '#dashboard_scan_macro_file', async function () {
    const file = this.files?.[0]
    if (!file) {
        clearDashboardScanMacroSelection()
        return
    }
    DASHBOARD_SCAN_MACRO_IMPORT_STATE.prepared = null
    DASHBOARD_SCAN_MACRO_IMPORT_STATE.fileName = String(file.name || '')
    updateDashboardScanMacroFileUi(DASHBOARD_SCAN_MACRO_IMPORT_STATE.fileName)
    setDashboardScanMacroStatus('Validating macro...', 'info')
    try {
        DASHBOARD_SCAN_MACRO_IMPORT_STATE.text = await file.text()
        await prepareSelectedDashboardScanMacro()
    } catch (error) {
        DASHBOARD_SCAN_MACRO_IMPORT_STATE.prepared = null
        renderDashboardScanMacroRuntimeFields(null)
        setDashboardScanMacroStatus(error?.message || 'Unable to import this macro.', 'error')
    }
})

$(document).on('change', '#dashboard_scan_macro_format', function () {
    if (!DASHBOARD_SCAN_MACRO_IMPORT_STATE.text) return
    setDashboardScanMacroStatus('Validating macro...', 'info')
    prepareSelectedDashboardScanMacro().catch((error) => {
        DASHBOARD_SCAN_MACRO_IMPORT_STATE.prepared = null
        renderDashboardScanMacroRuntimeFields(null)
        setDashboardScanMacroStatus(error?.message || 'Unable to import this macro.', 'error')
    })
})

$(document).on('click', '#dashboard_scan_macro_clear', function () {
    clearDashboardScanMacroSelection()
    return false
})

$(document).on('click', '#dashboard_dast_advanced_toggle', function () {
    const expanded = $(this).attr('aria-expanded') === 'true'
    setDashboardDastAdvancedSettingsExpanded(!expanded)
    $dashboardRunScansModal.modal('refresh')
    return false
})

$(document).on("click", "#manage_scans", function () {
    window._ptkReloadWarningClosed = false
    ; (async () => {
        applyDashboardReleaseVisibility()
        const activeTab = getDashboardCachedActiveTab() || await resolveActiveTab({ activeTab: controller.activeTab })
        const opened = await populateManageScansDialog({
            scans: getDashboardCachedScans(),
            policyState: controller.policyState || {}
        }, activeTab, { updateRuntime: false })
        if (opened === false) return

        resetDashboardManageScansModalState()
        $('#run_scan_dlg')
            .modal({
                allowMultiple: true,
                onShow: function () {
                    resetDashboardManageScansModalState()
                },
                onHidden: function () {
                    resetDashboardManageScansModalState()
                },
                onApprove: function () {
                    const $approve = $('#run_scan_dlg .confirm_scan_run')
                    if ($approve.hasClass('disabled') || dashboardActionInProgress || dashboardExportInProgress) {
                        return false
                    }
                    const currentActiveTab = controller.activeTab || activeTab
                    if (!currentActiveTab?.url || typeof currentActiveTab?.tabId === 'undefined') {
                        $('#result_header').text("Error")
                        $('#result_message').text("Active tab not set. Reload required tab to activate tracking.")
                        $('#result_dialog').modal('show')
                        return false
                    }
                    const contentReady = controller._contentReadyByTabId?.[currentActiveTab.tabId] === true
                    const host = new URL(currentActiveTab.url).host
                    let $form = $('#index_scans_form'), values = $form.form('get values')
                    let s = {
                        dast: values['dast_scan'] == 'on' ? true : false,
                        iast: values['iast_scan'] == 'on' ? true : false,
                        sast: values['sast_scan'] == 'on' ? true : false,
                        sca: values['sca_scan'] == 'on' ? true : false,
                    }
                    clearDashboardProPolicyValidation()
                    const sastPolicyValue = String($('#sast-scan-policy').val() || '').trim()
                    let sastScanStrategy = Number($('#sast-scan-strategy').val() || 0)
                    if (!Number.isFinite(sastScanStrategy)) {
                        sastScanStrategy = 0
                    }
                    const dastPolicyValue = String($('#dast-scan-policy').val() || '').trim()
                    const safetyProfile = ($('#dast-safety-profile').val() || 'safe').toLowerCase()
                    const portalSelections = collectDashboardPortalSelections()
                    const settings = {
                        maxRequestsPerSecond: $('#maxRequestsPerSecond').val(),
                        concurrency: $('#concurrency').val(),
                        sastScanStrategy: sastScanStrategy || 0,
                        scanStrategy: $('#dast-scan-strategy').val() || 'SMART',
                        dastRecordMacro: isDashboardDastRecordMacroEnabled(),
                        enableHtmlLinkDiscovery: isDashboardHtmlLinkDiscoveryEnabled(),
                        htmlLinkDiscoveryBudget: getDashboardHtmlLinkDiscoveryBudget(),
                        dastScanPolicy: parseDashboardPortalOptionValue(dastPolicyValue)
                            ? 'PORTAL'
                            : (dastPolicyValue || getDashboardPolicyDefaultValue('dast')),
                        safetyProfile,
                        scanControls: {
                            profile: safetyProfile
                        },
                        runCve: isRunCveEnabled(),
                        portalSelections
                    }
                    if (!contentReady && (s.iast || s.sast)) {
                        setReloadWarning($('#ptk_reload_warning'), true)
                        return false
                    }
                    if (DASHBOARD_SCAN_MACRO_IMPORT_STATE.text && !DASHBOARD_SCAN_MACRO_IMPORT_STATE.prepared) {
                        setDashboardScanMacroStatus('Resolve the macro import error before starting scans.', 'error')
                        return false
                    }
                    if (DASHBOARD_SCAN_MACRO_IMPORT_STATE.prepared && !Object.values(s).some(Boolean)) {
                        setDashboardScanMacroStatus('Select at least one scan engine to replay this macro.', 'error')
                        return false
                    }
                    let scanMacroSelection = null
                    try {
                        scanMacroSelection = compileSelectedDashboardScanMacro(currentActiveTab)
                    } catch (error) {
                        setDashboardScanMacroStatus(error?.message || 'The macro cannot be replayed.', 'error')
                        return false
                    }
                    if (scanMacroSelection && settings.dastRecordMacro) {
                        setDashboardScanMacroStatus('Macro replay and macro recording cannot run at the same time.', 'error')
                        return false
                    }
                    const jobs = []
                    if (s.dast) {
                        DASHBOARD_DAST_MACRO_STATE.requested = !!settings.dastRecordMacro
                        DASHBOARD_DAST_MACRO_STATE.started = false
                        jobs.push({
                            label: 'DAST',
                            run: async () => {
                                const response = await controller.runBackgroundScan(currentActiveTab.tabId, host, $('#scan_domains').val(), { dast: true, iast: false, sast: false, sca: false }, settings)
                                if (response?.success === false) {
                                    DASHBOARD_DAST_MACRO_STATE.requested = false
                                    DASHBOARD_DAST_MACRO_STATE.started = false
                                    throw new Error(response?.message || response?.error || 'scan_start_failed')
                                }
                                if (settings.dastRecordMacro) {
                                    const recordingResult = await startDashboardDastMacroRecording(currentActiveTab)
                                    if (recordingResult?.success === false) {
                                        showDashboardResultModal('Warning', recordingResult?.error || 'DAST scan started, but macro recording could not be started.', {
                                            header: 'Warning',
                                            type: 'warning'
                                        })
                                    }
                                }
                                return response
                            }
                        })
                    }
                    if (s.iast) {
                        jobs.push({
                            label: 'IAST',
                            run: async () => {
                                const response = await controller.runBackgroundScan(currentActiveTab.tabId, host, $('#scan_domains').val(), { dast: false, iast: true, sast: false, sca: false }, settings)
                                if (response?.success === false) {
                                    throw new Error(response?.message || response?.error || 'scan_start_failed')
                                }
                                return response
                            }
                        })
                    }
                    if (s.sast) {
                        jobs.push({
                            label: 'SAST',
                            run: async () => {
                                const response = await controller.runBackgroundScan(currentActiveTab.tabId, host, $('#scan_domains').val(), { dast: false, iast: false, sast: true, sca: false }, settings)
                                if (response?.success === false) {
                                    throw new Error(response?.message || response?.error || 'scan_start_failed')
                                }
                                return response
                            }
                        })
                    }
                    if (s.sca) {
                        jobs.push({
                            label: 'SCA',
                            run: async () => {
                                const response = await controller.runBackgroundScan(currentActiveTab.tabId, host, $('#scan_domains').val(), { dast: false, iast: false, sast: false, sca: true }, settings)
                                if (response?.success === false) {
                                    throw new Error(response?.message || response?.error || 'scan_start_failed')
                                }
                                return response
                            }
                        })
                    }
                    if (scanMacroSelection) {
                        jobs.push({
                            label: 'Macro replay',
                            requiresAnyPreviousSuccess: true,
                            run: async () => startDashboardScanMacroReplay(currentActiveTab, scanMacroSelection)
                        })
                    }
                    runDashboardProgressAction({
                        title: 'Run scans',
                        initialMessage: 'Preparing selected scans...',
                        jobs,
                        successMessage: 'Selected scans started.',
                        emptyMessage: 'No scans selected to run.',
                        activeTab: currentActiveTab,
                        trigger: $approve
                    }).then(() => {
                        setTimeout(() => {
                            $('#run_scan_dlg').modal('hide')
                        }, 350)
                    }).catch(() => { })
                    return false
                }
            })
            .modal('show')
        bindDashboardHelpPopups()

        refreshDashboardScanState(activeTab)
            .then((refreshed) => populateManageScansDialog(
                refreshed,
                refreshed?.activeTab || controller.activeTab || activeTab,
                { updateRuntime: true }
            ))
            .catch(() => { })
    })().catch(() => { })

    return false
})

$(document).on('click', '#load_pro_policies_button', async function () {
    if (!PRO_UI_VISIBLE) return false
    if (dashboardActionInProgress || dashboardExportInProgress) return false
    setDashboardPortalPolicyLoading(true)
    try {
        const result = await controller.loadPolicyMetadata()
        if (result?.success) {
            const clearedState = await clearDashboardLoadedPolicySelections()
            renderDashboardPortalPolicyState(clearedState)
            clearDashboardProPolicyValidation()
            showDashboardResultModal(
                'Success',
                buildDashboardPolicyLoadSuccessMessage(clearedState || {}),
                { type: 'success' }
            )
        } else {
            renderDashboardPortalPolicyState(result?.policyState || controller.policyState)
            showDashboardResultModal(
                'Error',
                buildPolicyLoadErrorMessage(result),
                { type: 'error', showSettings: result?.error === 'missing_api_key' }
            )
        }
    } catch (err) {
        showDashboardResultModal(
            'Error',
            buildPolicyLoadErrorMessage({ message: err?.message || 'unknown_error' }),
            { type: 'error' }
        )
    } finally {
        setDashboardPortalPolicyLoading(false)
    }
    return false
})

$(document).on('click', '#result_dialog .result_open_settings_btn', function () {
    openExtensionSettingsWindow()
    $('#result_dialog').modal('hide')
    return false
})

$(document).on('click', '#manage_scans, #run_scan_dlg .close, #result_dialog .close, #result_dialog .approve, #result_dialog .cancel', function () {
    hideDashboardHelpPopups()
})

$(document).on('change', '.dashboard-pro-policy-select', async function () {
    if (dashboardActionInProgress || dashboardExportInProgress) return false
    const $select = $(this)
    const engine = String($select.data('engine') || '').trim().toUpperCase()
    if (!engine) return false
    const rawValue = String($select.val() || '').trim()
    setDashboardPolicyUiValue(engine, rawValue)
    const policyId = parseDashboardPortalOptionValue(rawValue)
    const policyName = policyId ? String($select.find('option:selected').text() || '').trim() : null
    setDashboardPortalPolicyLoading(true)
    try {
        const shouldSelectPolicy = !!policyId
        const result = shouldSelectPolicy
            ? await controller.selectPolicy(engine, policyId, policyName)
            : await controller.clearPolicy(engine)
        if (result?.success) {
            renderDashboardPortalPolicyState(result.policyState)
            clearDashboardProPolicyValidation()
        } else {
            renderDashboardPortalPolicyState(result?.policyState || controller.policyState)
            showDashboardPolicyDialog(`Failed to update ${engine} scan policy: ${getDashboardPortalErrorMessage(result)}`, { header: 'Error', type: 'error' })
        }
    } catch (err) {
        showDashboardPolicyDialog(`Failed to update ${engine} scan policy: ${err?.message || 'unknown_error'}`, { header: 'Error', type: 'error' })
    } finally {
        setDashboardPortalPolicyLoading(false)
    }
    return false
})



/* Chrome runtime events handlers */
browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.channel == "ptk_content2popup" && message.type == "init_complete") {
        controller.storage = message.data.auth
        if (controller.tabId) {
            controller._contentReadyByTabId = controller._contentReadyByTabId || {}
            controller._contentReadyByTabId[controller.tabId] = true
            clearContentTimeout(controller.tabId)
        }
        bindStorage(true)
        $('#storage_no_access').hide()
        controller.complete(message.data)
        //setTimeout(function () { controller.complete(message.data) }, 500) //TODO - remove timeout, but keep cookies 
    }

    if (message.channel == "ptk_background2popup_dashboard") {
        //Object.assign(controller, message.data)

        if (message.type == "init_complete") {
            Object.assign(controller, message.data)
            bindCookies()
            bindHeaders()
        }
        if (message.type == "cookies_loaded") {
            if (Number.isInteger(message.data?.tabId) && Number.isInteger(controller.tabId) && message.data.tabId !== controller.tabId) {
                return
            }
            Object.assign(controller, message.data)
            bindCookies()
        }

        if (message.type == "analyze_complete") {
            // Clear any pending analysis timeout
            if (window._ptkAnalysisTimeout) {
                clearTimeout(window._ptkAnalysisTimeout)
                window._ptkAnalysisTimeout = null
            }
            controller._analysisRequested = false

            let technologies = []
            if (Array.isArray(controller.tab?.technologies)) {
                technologies = technologies.concat(controller.tab.technologies)
            }
            if (Array.isArray(message.data?.tab?.technologies)) {
                technologies = technologies.concat(message.data.tab.technologies)
            }
            Object.assign(controller, message.data)
            if (!controller.storage && controller.tab?.storage) {
                controller.storage = controller.tab.storage
            }
            if (technologies.length > 0 && controller.tab) {
                controller.tab.technologies = mergeTechnologyRows(technologies)
            }

            bindTechnologies(true)
            bindCVEs(true)

        }

        if (message.type == "headers_update") {
            const tabId = message.tabId
            if (!tabId || tabId !== controller.tabId) return
            if (message.requestId && controller._lastHeadersRequestId && message.requestId !== controller._lastHeadersRequestId) {
                return
            }
            const sig = message.sig || ''
            if (sig && controller._headersSig === sig) return
            controller._headersSig = sig
            controller.tab = controller.tab || {}
            if (message.owasp?.findings) {
                controller.tab.findings = message.owasp.findings
            }
            if (message.requestHeaders) {
                controller.tab.requestHeaders = message.requestHeaders
            }
            if (message.status === "error") {
                $('.loader.owasp').hide()
                return
            }
            bindOWASP()
            bindHeaders()
        }
    }
})
