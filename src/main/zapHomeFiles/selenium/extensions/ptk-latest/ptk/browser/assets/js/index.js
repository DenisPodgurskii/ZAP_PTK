/* Author: Denis Podgurskii */
import { ptk_controller_index } from "../../../controller/index.js"
import { ptk_jwtHelper } from "../../../background/utils.js"
import * as rutils from "../js/rutils.js"
const controller = new ptk_controller_index()
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
let dashboardActionInProgress = false

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
    $('#run_scan_dlg .confirm_scan_run').toggleClass('disabled', actionBusy)
    $('#run_scan_dlg .dast_scan_stop, #run_scan_dlg .iast_scan_stop, #run_scan_dlg .sast_scan_stop, #run_scan_dlg .sca_scan_stop')
        .toggleClass('disabled', actionBusy)
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
        const $popup = $icon.closest('.field').children('.ptk-help-popup').first()
        if (!$popup.length) return
        if ($icon.data('module-popup')) {
            $icon.popup('destroy')
        }
        $icon.popup({
            popup: $popup,
            inline: true,
            hoverable: true,
            position: resolveDashboardHelpPopupPosition($icon),
            delay: {
                show: 300,
                hide: 800
            }
        })
    })
}

async function refreshDashboardScanState(activeTab = null) {
    const resolvedTab = activeTab || controller.activeTab || (controller.tabId ? { tabId: controller.tabId, url: controller.url } : null)
    const refreshed = await controller.init(resolvedTab ? { tabId: resolvedTab.tabId, url: resolvedTab.url } : {})
    applyDashboardScanControls(refreshed?.scans)
    return refreshed
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
            return refreshed
        }

        const errors = []
        const total = queue.length
        for (let i = 0; i < total; i += 1) {
            const job = queue[i]
            const base = Math.floor((i / total) * 100)
            const done = Math.floor(((i + 1) / total) * 100)
            setDashboardExportProgress(base, `${job.label}: in progress...`, { title })
            try {
                await Promise.resolve(job.run())
                setDashboardExportProgress(done, `${job.label}: complete`, { title })
            } catch (err) {
                errors.push(`${job.label}: ${err?.message || 'action_failed'}`)
                setDashboardExportProgress(done, `${job.label}: failed`, { title })
            }
        }

        if (errors.length) {
            setDashboardExportProgress(100, `${successMessage || title} complete with ${errors.length} error(s).`, { title })
            console.error(`[PTK Dashboard] ${title} errors`, errors)
        } else {
            setDashboardExportProgress(100, successMessage || `${title} complete.`, { title })
        }

        const refreshed = await refreshDashboardScanState(activeTab)
        return refreshed
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

function resetDashboardCardsForTabChange() {
    controller.tab = {}
    controller.storage = null
    controller.cookies = {}
    controller._headersSig = null
    controller._lastHeadersRequestId = null
    tokens = []
    tokenAdded = false
    $('#jwt_btn').hide()
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
    if (result?.activeTab?.url && typeof result?.activeTab?.tabId !== 'undefined' && !isExtensionUrl(result.activeTab.url)) {
        return result.activeTab
    }
    try {
        const tabs = await browser.tabs.query({ currentWindow: true })
        const active = tabs && tabs.length ? tabs.find((tab) => tab.active) : null
        if (active?.url && typeof active?.id !== 'undefined' && !isExtensionUrl(active.url)) {
            return { url: active.url, tabId: active.id }
        }
        if (controller._lastAppTabId) {
            const last = tabs.find((tab) => tab.id === controller._lastAppTabId)
            if (last?.url && !isExtensionUrl(last.url)) {
                return { url: last.url, tabId: last.id }
            }
        }
        const fallback = tabs.find((tab) => tab?.url && !isExtensionUrl(tab.url))
        if (fallback?.url && typeof fallback?.id !== 'undefined') {
            return { url: fallback.url, tabId: fallback.id }
        }
    } catch (_) { }
    return null
}

function isExtensionUrl(url) {
    if (!url) return false
    const base = browser.runtime.getURL('')
    return url.startsWith(base)
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
    if (activeTab.url && !isExtensionUrl(activeTab.url)) {
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

    $runCveInput = $('#ptk_dast_run_cve')
    $runCveCheckboxWrapper = $runCveInput.closest('.ui.checkbox')

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

    setRunCveState(false)

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
        const openReport = () => {
            const url = browser.runtime.getURL("/ptk/browser/report.html?full_report")
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
        browser.storage.local.set({
            "tab_full_info":
            {
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
        }).then(function () {
            return openReport()
        }).catch(() => {
            return openReport()
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

    setTimeout(function () {
        resolveActiveTab().then((activeTab) => {
            const initOpts = activeTab?.tabId ? { tabId: activeTab.tabId, url: activeTab.url } : {}
            return controller.init(initOpts).then((result) => handleDashboardInit(result, activeTab))
        }).catch(() => {
            controller.init().then((result) => handleDashboardInit(result, null)).catch(() => {})
        })
    }, 150)

    setupCardToggleHandlers()

    rutils.registerDashboardTabListener({
        onTabChange: ({ tabId, url }) => {
            if (controller.tabId === tabId && controller.url === url) return
            resetDashboardCardsForTabChange()
            controller.tabId = tabId
            controller.url = url
            controller._lastAppTabId = tabId
            controller._lastAppTabUrl = url
            rutils.updateDashboardTab(tabId, url)
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
        $('#tbl_storage').DataTable().row.add(['Cookie', `<a href="#" class="storage_auth_link" data="cookie">View</a>`]).draw()


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
            columnDefs: [{
                "visible": false, "targets": groupColumn
            }],
            "order": [[groupColumn, 'asc']],
            "drawCallback": function (settings) {
                var api = this.api();
                var rows = api.rows({ page: 'current' }).nodes();
                var last = null;

                api.column(groupColumn, { page: 'current' }).data().each(function (group, i) {
                    if (last !== group) {
                        $(rows).eq(i).before(
                            '<tr class="group" ><td colspan="3"><div class="ui black ribbon label">' + group + '</div></td></tr>'
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
            tokens.push(['cookie', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
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
            data: dt
        }

        bindTable('#tbl_headers', params)

        let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.headersRegex)
        if (jwtToken) {
            let jwt = JSON.parse(decodedToken)
            tokens.push(['headers', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
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
    let params = { "data": dt, "columns": [{ width: "45%" }, { width: "30%" }, { width: "25%" }] }

    bindTable('#tbl_technologies', params)
    $('.loader.technologies').hide()
    updateGenerateReport(controller.scans)
}

async function bindCVEs(force = false) {
    let dt = new Array()
    if (Array.isArray(controller.tab?.cves)) {
        controller.tab.cves.forEach(item => {
            const evidence = item.evidence || {}
            const evidenceText = `H:${evidence.headers || 0} / HTML:${evidence.html || 0} / JS:${evidence.js || 0}`
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
    let params = { "data": dt }
    bindTable('#tbl_cves', params)
    $('.loader.cves').hide()
    updateGenerateReport(controller.scans)
}

async function bindTokens(data) {
    if (tokens.length > 0) {
        if (!tokenAdded) {
            $('#tbl_storage').DataTable().row.add(['Tokens', `<a href="#" class="storage_auth_link" data="tokens">View</a>`]).draw()
            tokenAdded = true
        }
        $("a[data-tab='tokens']").show()
        bindTable('#tbl_tokens', { data: tokens })
        controller.save(JSON.parse(JSON.stringify(tokens)))
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
            tokens.push(['localStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
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
            tokens.push(['sessionStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
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
            run: async () => controller.stopBackgroundScan({ dast: true, iast: false, sast: false, sca: false })
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
    if (scans.dast) {
        jobs.push({ label: 'DAST', run: async () => controller.stopBackgroundScan({ dast: true, iast: false, sast: false, sca: false }) })
    }
    if (scans.iast) {
        jobs.push({ label: 'IAST', run: async () => controller.stopBackgroundScan({ dast: false, iast: true, sast: false, sca: false }) })
    }
    if (scans.sast) {
        jobs.push({ label: 'SAST', run: async () => controller.stopBackgroundScan({ dast: false, iast: false, sast: true, sca: false }) })
    }
    if (scans.sca) {
        jobs.push({ label: 'SCA', run: async () => controller.stopBackgroundScan({ dast: false, iast: false, sast: false, sca: true }) })
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

$(document).on("click", "#manage_scans", function () {
    window._ptkReloadWarningClosed = false
    const initOpts = controller.tabId ? { tabId: controller.tabId, url: controller.url } : {}
    controller.init(initOpts).then(function (result) {
        const resolvedTabPromise = controller.tabId
            ? Promise.resolve({ tabId: controller.tabId, url: controller.url })
            : resolveActiveTab(result)
        return resolvedTabPromise.then(async function (activeTab) {
            if (!activeTab?.url || typeof activeTab?.tabId === 'undefined') {
                $('#result_header').text("Error")
                $('#result_message').text("Active tab not set. Reload required tab to activate tracking.")
                $('#result_dialog').modal('show')
                return false
            }
            result.activeTab = activeTab
            controller.activeTab = activeTab

            let h = new URL(result.activeTab.url).host
            $('#scan_host').text(h)
            $('#scan_domains').text(h)
            applyDashboardScanControls(result?.scans)

            let settings = result.scans.dastSettings
            $('#maxRequestsPerSecond').val(settings.maxRequestsPerSecond)
            $('#concurrency').val(settings.concurrency)
            $('#dast-scan-strategy').val(settings.dastScanStrategy || 'SMART')
            $('#dast-scan-policy').val(settings.dastScanPolicy || 'ACTIVE')
            const dashboardSafetyProfile = (
                settings?.scanControls?.profile ||
                settings?.safetyProfile ||
                'safe'
            )
            $('#dast-safety-profile').val(String(dashboardSafetyProfile).toLowerCase())
            setRunCveState(false)
            const contentReady = await rutils.pingContentScript(activeTab.tabId, { timeoutMs: 1800 })
            setReloadWarning($('#ptk_reload_warning'), !contentReady)
            updateRuntimeScanToggles(contentReady)

            $('#run_scan_dlg')
                .modal({
                    allowMultiple: true,
                    onApprove: function () {
                        const $approve = $('#run_scan_dlg .confirm_scan_run')
                        if ($approve.hasClass('disabled') || dashboardActionInProgress || dashboardExportInProgress) {
                            return false
                        }
                        let $form = $('#index_scans_form'), values = $form.form('get values')
                        let s = {
                            dast: values['dast_scan'] == 'on' ? true : false,
                            iast: values['iast_scan'] == 'on' ? true : false,
                            sast: values['sast_scan'] == 'on' ? true : false,
                            sca: values['sca_scan'] == 'on' ? true : false,
                        }
                        let sastScanStrategy = $('#sast-scan-strategy').val()
                        const safetyProfile = ($('#dast-safety-profile').val() || 'safe').toLowerCase()
                        const settings = {
                            maxRequestsPerSecond: $('#maxRequestsPerSecond').val(),
                            concurrency: $('#concurrency').val(),
                            sastScanStrategy: sastScanStrategy || 0,
                            scanStrategy: $('#dast-scan-strategy').val() || 'SMART',
                            dastScanPolicy: $('#dast-scan-policy').val() || 'ACTIVE',
                            safetyProfile,
                            scanControls: {
                                profile: safetyProfile
                            },
                            runCve: isRunCveEnabled()
                        }
                        if (!contentReady && (s.iast || s.sast)) {
                            setReloadWarning($('#ptk_reload_warning'), true)
                            return false
                        }
                        const jobs = []
                        if (s.dast) {
                            jobs.push({
                                label: 'DAST',
                                run: async () => controller.runBackgroundScan(result.activeTab.tabId, h, $('#scan_domains').val(), { dast: true, iast: false, sast: false, sca: false }, settings)
                            })
                        }
                        if (s.iast) {
                            jobs.push({
                                label: 'IAST',
                                run: async () => controller.runBackgroundScan(result.activeTab.tabId, h, $('#scan_domains').val(), { dast: false, iast: true, sast: false, sca: false }, settings)
                            })
                        }
                        if (s.sast) {
                            jobs.push({
                                label: 'SAST',
                                run: async () => controller.runBackgroundScan(result.activeTab.tabId, h, $('#scan_domains').val(), { dast: false, iast: false, sast: true, sca: false }, settings)
                            })
                        }
                        if (s.sca) {
                            jobs.push({
                                label: 'SCA',
                                run: async () => controller.runBackgroundScan(result.activeTab.tabId, h, $('#scan_domains').val(), { dast: false, iast: false, sast: false, sca: true }, settings)
                            })
                        }
                        runDashboardProgressAction({
                            title: 'Run scans',
                            initialMessage: 'Preparing selected scans...',
                            jobs,
                            successMessage: 'Selected scans started.',
                            emptyMessage: 'No scans selected to run.',
                            activeTab: result.activeTab,
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
        })
    })

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
