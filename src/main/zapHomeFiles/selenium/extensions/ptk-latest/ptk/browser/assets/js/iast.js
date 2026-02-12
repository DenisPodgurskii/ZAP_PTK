/* Author: Denis Podgurskii */
import { ptk_controller_iast } from "../../../controller/iast.js"
import { ptk_controller_rbuilder } from "../../../controller/rbuilder.js"
import { ptk_utils } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import * as rutils from "../js/rutils.js"
import { normalizeScanResult } from "../js/scanResultViewModel.js"
import { normalizeCwe, normalizeOwasp, toLegacyOwaspString } from "../../../background/common/normalizeMappings.js"

const controller = new ptk_controller_iast()
const request_controller = new ptk_controller_rbuilder()
const decoder = new ptk_decoder()
const iastFilterState = {
    scope: 'all',
    requestKey: null
}
const IAST_SEVERITY_ORDER = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4
}
const IAST_UNKNOWN_REQ = "__ptk_unknown__"
const IAST_COUNTERS = buildIastCounters()
const IAST_REQUEST_COUNTERS = new Map()
const IAST_DELTA_QUEUE = []
const IAST_FLUSH_INTERVAL_MS = 300
let iastFlushTimer = null
let iastRequestFilterDirty = false

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

function showResultModal(header, message) {
    $('#result_header').text(header)
    $('#result_message').text(message || '')
    $('#result_dialog').modal('show')
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
    if (!finding) return null
    const loc = finding.location || {}
    const evidenceEntry = extractPrimaryIastEvidence(finding)
    const ev = evidenceEntry || {}
    const severity = formatIastSeverityLabel(finding.severity || 'info')
    const metaRule =
        finding.ruleName
        || finding.metadata?.name
        || finding.module_metadata?.name
        || finding.moduleName
        || ev.message
        || finding.category
        || finding.ruleId
        || finding.id
        || `Finding ${index + 1}`
    const taintSource = ev.taintSource || finding.taintSource || finding.source || null
    const sinkId = ev.sinkId || finding.sinkId || finding.sink || null
    const baseContext = Object.assign({}, ev.context || {}, finding.context || {})
    const flow = Array.isArray(baseContext.flow) ? baseContext.flow : []
    const tracePayload = ev.trace || baseContext.trace || finding.trace || null
    const description = finding.description || finding.metadata?.description || ev.message || ''
    const recommendation = finding.recommendation || finding.metadata?.recommendation || ''
    const links = mergeLinkMaps(
        finding.links,
        finding.metadata?.links,
        finding.module_metadata?.links
    )
    const contextPayload = Object.assign(
        {
            flow,
            domPath: baseContext.domPath || ev.domPath || loc.domPath || null,
            elementOuterHTML: baseContext.elementOuterHTML || ev.elementOuterHTML || null,
            value: baseContext.value || ev.value || null,
            url: baseContext.url || loc.url || null,
            elementId: baseContext.elementId || loc.elementId || null,
            tagName: baseContext.tagName || ev.tagName || null
        },
        baseContext
    )
    const owaspArray = Array.isArray(finding.owasp) ? finding.owasp : []
    const owaspPrimary = finding.owaspPrimary || (owaspArray.length ? owaspArray[0] : null)
    const owaspLegacy = finding.owaspLegacy || toLegacyOwaspString(owaspArray)
    const normalizedEvidenceEntry = {
        source: 'IAST',
        taintSource,
        sinkId,
        schemaVersion: ev.schemaVersion || null,
        primaryClass: ev.primaryClass || null,
        sourceRole: ev.sourceRole || null,
        origin: ev.origin || null,
        observedAt: ev.observedAt || null,
        operation: ev.operation || null,
        detection: ev.detection || null,
        routing: ev.routing || null,
        context: contextPayload,
        matched: ev.matched || finding.matched || null,
        trace: tracePayload,
        traceSummary: ev.traceSummary || null,
        flowSummary: ev.flowSummary || null,
        sourceKind: ev.sourceKind || null,
        sourceKey: ev.sourceKey || null,
        sourceValuePreview: ev.sourceValuePreview || null,
        sources: ev.sources || null,
        primarySource: ev.primarySource || null,
        secondarySources: ev.secondarySources || null,
        sinkContext: ev.sinkContext || null,
        sinkSummary: ev.sinkSummary || finding.sinkSummary || null,
        taintSummary: ev.taintSummary || finding.taintSummary || null,
        allowedSources: ev.allowedSources || finding.allowedSources || null,
        raw: {
            severity,
            meta: { ruleName: metaRule },
            sinkId,
            source: taintSource,
            type: finding.category || null,
            owasp: owaspArray,
            cwe: Array.isArray(finding.cwe) ? finding.cwe : [],
            tags: finding.tags || [],
            location: loc,
            context: contextPayload
        }
    }
    const affectedUrls = []
    const seenUrls = new Set()
    const addUrl = (value, { prepend = false } = {}) => {
        if (!value) return
        const str = String(value).trim()
        if (!str || seenUrls.has(str)) return
        seenUrls.add(str)
        if (prepend) {
            affectedUrls.unshift(str)
        } else {
            affectedUrls.push(str)
        }
    }
    addUrl(loc.url, { prepend: true })
    if (Array.isArray(ev.affectedUrls)) {
        ev.affectedUrls.forEach(url => addUrl(url))
    }
    if (Array.isArray(finding.affectedUrls)) {
        finding.affectedUrls.forEach(url => addUrl(url))
    }
    addUrl(ev?.context?.url)
    addUrl(ev?.context?.location)
    return {
        id: finding.id || `iast-${index}`,
        ruleId: finding.ruleId || finding.id || `rule-${index}`,
        ruleName: metaRule,
        severity,
        category: finding.category || null,
        confidence: Number.isFinite(finding.confidence) ? finding.confidence : null,
        owasp: owaspArray,
        owaspPrimary,
        owaspLegacy,
        cwe: Array.isArray(finding.cwe) ? finding.cwe : [],
        tags: finding.tags || [],
        location: loc,
        affectedUrls: affectedUrls.filter(Boolean),
        evidence: [normalizedEvidenceEntry],
        context: contextPayload,
        trace: tracePayload,
        description,
        recommendation,
        links,
        metadata: {
            id: finding.ruleId || finding.id || `rule-${index}`,
            name: metaRule,
            severity,
            description,
            recommendation,
            links
        },
        module_metadata: {
            id: finding.module_metadata?.id || finding.moduleId || null,
            name: finding.module_metadata?.name || finding.moduleName || null,
            links: finding.module_metadata?.links || links
        },
        requestId: index,
        __index: index,
        type: 'iast',
        source: taintSource,
        sink: sinkId
    }
}

function getIastAttackItem(index) {
    if (Number.isNaN(Number(index))) return null
    const items = Array.isArray(controller?.iastAttackItems) ? controller.iastAttackItems : null
    if (items && items[index]) return items[index]
    const legacyItems = controller?.scanResult?.scanResult?.items
    if (Array.isArray(legacyItems)) return legacyItems[index] || null
    return null
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

    $(document).on("click", ".save_report", function () {
        let el = $(this).parent().find(".loader")
        el.addClass("active")
        controller.saveReport().then(function (result) {
            if (result?.success) {
                $('#result_header').text("Success")
                $('#result_message').text("Scan saved")
                $('#result_dialog').modal('show')
            } else {
                $('#result_header').text("Error")
                $('#result_message').text(result?.json?.message)
                $('#result_dialog').modal('show')
            }

            el.removeClass("active")
        })
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
                        if (!contentReady) {
                            $('#ptk_scan_reload_warning').show()
                            return false
                        }
                        controller.runBackgroundScan(result.activeTab.tabId, h, scanStrategy).then(function (result) {
                            $("#request_info").html("")
                            $("#attacks_info").html("")
                            triggerIastStatsEvent(result.scanResult)
                            changeView(result)
                        })
                    }
                })
                .modal('show')
            $('#iast_scans_form .question')
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
        $('#download_scans').modal('show')
        controller.downloadScans().then(function (result) {

            if (!result?.success) {
                $("#download_error").text(result.json.message)
                $("#download_scans_error").show()
                return
            }

            $("#download_scans_error").hide()
            let dt = new Array()
            result?.json.forEach(item => {
                item.scans.forEach(scan => {
                    let link = `<div class="ui mini icon button download_scan_by_id" style="position: relative" data-scan-id="${scan.scanId}"><i class="download alternate large icon"
                                        title="Download"></i>
                                        <div style="position:absolute; top:1px;right: 2px">
                                             <div class="ui  centered inline inverted loader"></div>
                                        </div>
                                </div>`
                    let del = ` <div class="ui mini icon button delete_scan_by_id" data-scan-id="${scan.scanId}" data-scan-host="${item.hostname}"><i  class="trash alternate large icon "
                    title="Delete"></i></div>`
                    let d = new Date(scan.scanDate)
                    dt.push([item.hostname, scan.scanId, d.toLocaleString(), link, del])
                })
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
                                '<tr class="group" ><td colspan="4"><div class="ui black ribbon label">' + group + '</div></td></tr>'
                            );
                            last = group;
                        }
                    });
                }
            }

            bindTable('#tbl_scans', params)


        })
    })

    $(document).on("click", ".download_scan_by_id", function () {
        $(this).parent().find(".loader").addClass("active")
        let scanId = $(this).attr("data-scan-id")
        controller.downloadScanById(scanId).then(function (result) {
            let info = { isScanRunning: false, scanResult: result }
            changeView(info)
            if (hasRenderableIastData(info.scanResult)) {
                bindScanResult(info)
            }
            $('#download_scans').modal('hide')
        })
    })

    $('.import_export').on('click', function () {

        controller.init().then(function (result) {
            if (!hasRenderableIastData(result.scanResult)) {
                $('.export_scan_btn').addClass('disabled')
            } else {
                $('.export_scan_btn').removeClass('disabled')
            }
            $('#import_export_dlg').modal('show')
        })

    })

    $('.export_scan_btn').on('click', function () {
        controller.exportScanResult().then(function (scanResult) {
            if (scanResult && hasRenderableIastData(scanResult)) {
                let blob = new Blob([JSON.stringify(scanResult)], { type: 'text/plain' })
                let fName = "PTK_IAST_scan.json"

                let downloadLink = document.createElement("a")
                downloadLink.download = fName
                downloadLink.innerHTML = "Download File"
                downloadLink.href = window.URL.createObjectURL(blob)
                downloadLink.click()
            } else {
                showResultModal("Error", "Nothing to export yet.")
            }
        }).catch(err => {
            showResultModal("Error", err?.message || "Unable to export scan")
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
        var fileReader = new FileReader()
        fileReader.onload = function () {
            controller.save(fileReader.result).then(result => {
                changeView(result)
                if (hasRenderableIastData(result.scanResult)) {
                    bindScanResult(result)
                }
                $('#import_export_dlg').modal('hide')
            }).catch(e => {
                $('#result_message').text('Could not import IAST scan')
                $('#result_dialog').modal('show')
            })
        }

        fileReader.onprogress = (event) => {
            if (event.lengthComputable) {
            }
        }
        fileReader.readAsText(file)
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
        $('.generate_report').hide()
        $('.save_report').hide()
        //$('.exchange').hide()

        hideRunningForm()
        showWelcomeForm()
        controller.reset().then(function (result) {
            triggerIastStatsEvent(result.scanResult)
            if (Array.isArray(result?.default_modules) && result.default_modules.length) {
                bindModules(result)
            }
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
        changeView(result)
        if (hasRenderableIastData(result.scanResult)) {
            bindScanResult(result)
        } else if (!result.isScanRunning && Array.isArray(result?.default_modules) && result.default_modules.length) {
            bindModules(result)
            showWelcomeForm()
        } else if (!result.isScanRunning) {
            showWelcomeForm()
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
}

function hideWelcomeForm() {
    $('#welcome_message').hide()
    $('#main').show()
}

function showRunningForm(result) {
    setIastPageLoader(false)
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
    }
    else if (hasRenderableIastData(result.scanResult)) {
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
    $("#progress_message").hide()
    $('.generate_report').show()
    $('.save_report').show()
    $('#request_info').html("")
    $('#attacks_info').html("")
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
        // Keep bucket ordering; avoid DOM re-sorts.
        triggerIastStatsEvent(raw, vm)
        if (iastRequestFilterDirty) {
            updateRequestFilterActiveState()
            iastRequestFilterDirty = false
        }
        applyIastFilters()
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
        : (Array.isArray(result) ? result : [])
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
    $("#progress_attack_name").text(message.info.name)
    $("#progress_message").show()
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
    const dataset = extractIastDataset(source)
    const requestMap = new Map()
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
        const key = `${method} ${normalizedUrl}`
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
                key,
                method,
                displayUrl: primaryUrl || candidateUrls[0] || normalizedUrl,
                host,
                status: null,
                type: 'finding',
                url: normalizedUrl,
                lastSeen: Number.isNaN(lastSeenTs) ? Date.now() : lastSeenTs,
                _normalizedUrl: normalizedUrl,
                _uiKey: key
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
    iastFilterState.scope = normalized
    $('#filter_all').toggleClass('active', normalized === 'all')
    $('#filter_vuln').toggleClass('active', normalized === 'vuln')
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
                isScanRunning: !!message.isScanRunning
            }
            changeView(info)
            if (hasRenderableIastData(info.scanResult)) {
                bindScanResult(info)
            }
        }
        if (message?.type === 'scan_delta') {
            applyIastScanDelta(message)
        }
    }
})
