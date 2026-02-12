/* Author: Denis Podgurskii */
import { ptk_controller_sca } from "../../../controller/sca.js"
import { ptk_controller_rbuilder } from "../../../controller/rbuilder.js"
import { ptk_utils } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import * as rutils from "../js/rutils.js"

const controller = new ptk_controller_sca()
const request_controller = new ptk_controller_rbuilder()
const decoder = new ptk_decoder()
const SCA_SORT_SEVERITY = 'severity'
let scaComponents = []
let selectedComponentKey = null
let scaSortType = SCA_SORT_SEVERITY
const $scaSaveScanModal = $('#sca_save_scan_modal')
let $scaSaveScanProjectDropdown = $('#sca_save_scan_project_select')
const $scaSaveScanModalError = $('#sca_save_scan_modal_error')
const scaSaveScanProjectMap = new Map()
const $downloadScansModal = $('#download_scans')
let $scaDownloadProjectDropdown = $('#download_project_select')
const scaDownloadProjectMap = new Map()


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
            url: browser.runtime.getURL("/ptk/browser/report.html?sca_report")
        })
    })

    $(document).on("click", ".save_scan", function () {
        const $loader = $(this).find('.loader')
        requestScaProjectsAndShowModal($loader)
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
            window._ptkScaReloadWarningClosed = false
            const contentReady = await rutils.pingContentScript(result.activeTab.tabId, { timeoutMs: 700 })
            if (!window._ptkScaReloadWarningClosed) {
                $('#ptk_scan_reload_warning').toggle(!contentReady)
            }

            $('#run_scan_dlg')
                .modal({
                    allowMultiple: true,
                    onApprove: function () {
                        controller.runBackgroundScan(result.activeTab.tabId, h).then(function (result) {
                            clearScaPanels()
                            $(document).trigger("bind_stats", result.scanResult)
                            changeView(result)
                        })
                    }
                })
                .modal('show')
        })

        return false
    })

    $(document).on("click", "#ptk_scan_reload_warning_close_sca", function () {
        window._ptkScaReloadWarningClosed = true
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
        loadScaDownloadProjects()
    })

    $(document).on("click", ".download_scan_by_id", function () {
        $(this).parent().find(".loader").addClass("active")
        let scanId = $(this).attr("data-scan-id")
        controller.downloadScanById(scanId).then(function (result) {
            if (result?.success === false) {
                const message = result?.json?.message || result?.message || 'Unable to download scan'
                showScaResultModal('Error', message)
                return
            }
            let info = { isScanRunning: false, scanResult: result }
            changeView(info)
            if (Array.isArray(info.scanResult?.findings) && info.scanResult.findings.length > 0) {
                bindScanResult(info)
            }
            $('#download_scans').modal('hide')
        }).catch(err => {
            showScaResultModal('Error', err?.message || 'Unable to download scan')
        })
    })

    $('.import_export').on('click', function () {

        controller.init().then(function (result) {
            if (!Array.isArray(result.scanResult?.findings) || result.scanResult.findings.length === 0) {
                $('.export_scan_btn').addClass('disabled')
            } else {
                $('.export_scan_btn').removeClass('disabled')
            }
            $('#import_export_dlg').modal('show')
        })

    })

    $('.export_scan_btn').on('click', function () {
        controller.exportScanResult().then(function (scanResult) {
            if (Array.isArray(scanResult?.findings) && scanResult.findings.length > 0) {
                let blob = new Blob([JSON.stringify(scanResult)], { type: 'text/plain' })
                let fName = "PTK_SCA_scan.json"

                let downloadLink = document.createElement("a")
                downloadLink.download = fName
                downloadLink.innerHTML = "Download File"
                downloadLink.href = window.URL.createObjectURL(blob)
                downloadLink.click()
            } else {
                showScaResultModal('Error', 'Nothing to export yet.')
            }
        }).catch(err => {
            showScaResultModal('Error', err?.message || 'Unable to export scan')
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
                if (Array.isArray(result.scanResult?.findings) && result.scanResult.findings.length > 0) {
                    bindScanResult(result)
                }
                $('#import_export_dlg').modal('hide')
            }).catch(e => {
                $('#result_message').text('Could not import SCA scan')
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
            if (Array.isArray(result.scanResult?.findings) && result.scanResult.findings.length > 0) {
                bindScanResult(result)
            }
            $('#import_export_dlg').modal('hide')
        }).catch(e => {
            $('#result_message').text('Could not import SCA scan')
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
                            if (result?.success === false) {
                                $("#scan_delete_message").text(result?.json?.message || result?.message || 'Unable to delete scan')
                                return false
                            }
                            $('.cloud_download_scans').trigger("click")
                            return true
                        }).catch(err => {
                            $("#scan_delete_message").text(err?.message || 'Unable to delete scan')
                            return false
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
        clearScaPanels()
        $('.generate_report').hide()
        $('.save_scan').hide()
        //$('.exchange').hide()

        hideRunningForm()
        showWelcomeForm()
        controller.reset().then(function (result) {
            $(document).trigger("bind_stats", result.scanResult)
            //bindModules(result)
        })
    })

    $('.send_rbuilder').on("click", function () {
        let request = $('#raw_request').val().trim()
        window.location.href = "rbuilder.html?rawRequest=" + decoder.base64_encode(encodeURIComponent(JSON.stringify(request)))
        return false
    })


    $(document).on("click", ".btn_stacktrace", function () {
        let el = $(this).parent().find(".content.stacktrace")
        if (this.textContent.trim() == 'Show code snippet') {
            this.textContent = 'Hide code snippet'
            $(el).show()
        } else {
            $(this).parent().find(".content.stacktrace").hide()
            this.textContent = 'Show code snippet'
        }

    })

    $(document).on("click", ".close.icon.stacktrace", function () {
        $(this).parent().hide()
        $(this).parent().parent().find(".btn_stacktrace").text('Show code snippet')
    })

    $(document).on('click', '.sca-component-item', function () {
        const key = decodeURIComponent($(this).attr('data-component') || '').trim()
        selectScaComponent(key)
    })

    $(document).on('keydown', '.sca-component-item', function (event) {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault()
            const key = decodeURIComponent($(this).attr('data-component') || '').trim()
            selectScaComponent(key)
        }
    })



    $(document).on("bind_stats", function (e, scanResult) {
        if (scanResult?.stats) {
            rutils.bindStats(scanResult.stats, 'sca')
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
        if (Array.isArray(result.scanResult?.findings) && result.scanResult.findings.length > 0) {
            bindScanResult(result)
        } else {
            //bindModules(result)
        }
    })
    // $('.ui.accordion').accordion({
    //     onOpen: function () {
    //         let index = $(this).find('input[name="requestId"]').val()
    //         $('#filter_vuln').removeClass('active')
    //         $('#filter_all').addClass('active')
    //         $('.attack_info').hide()
    //         $('.attack_info.' + index).show()

    //         let stats = {
    //             attacksCount: $('.attack_info.' + index).length,
    //             vulnsCount: $('.attack_info.success.' + index).length,
    //             high: $('.attack_info.success.High.' + index).length,
    //             medium: $('.attack_info.success.Medium.' + index).length,
    //             low: $('.attack_info.success.Low.' + index).length
    //         }

    //         bindStats(stats)


    //     },
    //     onClose: function () {
    //         let index = $(this).find('input[name="requestId"]').val()
    //         $('#filter_vuln').removeClass('active')
    //         $('#filter_all').addClass('active')
    //         $('.attack_info').show()

    //         let stats = {
    //             attacksCount: $('.attack_info').length,
    //             vulnsCount: $('.attack_info.success').length,
    //             high: $('.attack_info.success.High').length,
    //             medium: $('.attack_info.success.Medium').length,
    //             low: $('.attack_info.success.Low').length
    //         }

    //         bindStats(stats)
    //     }
    // })

    renderScaComponentList()
    renderScaFindings()
})

function showScaResultModal(header, message) {
    $('#result_header').text(header)
    $('#result_message').text(message || '')
    $('#result_dialog').modal('show')
}

function handleScaSaveScanResponse(result) {
    if (result instanceof Error) {
        showScaResultModal('Error', result.message || 'Unable to save scan')
        return
    }
    if (result?.success) {
        showScaResultModal('Success', 'Scan saved')
    } else {
        const message = result?.json?.message || result?.message || 'Unable to save scan'
        showScaResultModal('Error', message)
    }
}

function extractScaProjectsFromPayload(payload) {
    if (!payload) return []
    if (Array.isArray(payload)) return payload
    if (typeof payload !== 'object') return []
    const containers = ['projects', 'data', 'items', 'findings', 'results']
    for (const key of containers) {
        const value = payload[key]
        if (!value) continue
        if (Array.isArray(value)) {
            return value
        }
        const nested = extractScaProjectsFromPayload(value)
        if (nested.length) {
            return nested
        }
    }
    return []
}

function normalizeScaProjectOption(project) {
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

function buildScaProjectOptions(payload) {
    const rawProjects = extractScaProjectsFromPayload(payload)
    const options = []
    rawProjects.forEach(project => {
        const option = normalizeScaProjectOption(project)
        if (option) {
            options.push(option)
        }
    })
    return options
}

function resetScaSemanticDropdown($dropdown) {
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

function rebuildScaDropdown($dropdown, map, projectOptions, placeholderText) {
    map.clear()
    if (!$dropdown || !$dropdown.length) return $dropdown
    try {
        $dropdown.dropdown('destroy')
    } catch (err) { }
    $dropdown = resetScaSemanticDropdown($dropdown)
    if (!$dropdown) return $dropdown
    const placeholder = document.createElement('option')
    placeholder.value = ''
    placeholder.textContent = placeholderText || 'Select a project'
    $dropdown.append(placeholder)
    projectOptions.forEach(opt => {
        const option = document.createElement('option')
        option.value = opt.value
        option.textContent = opt.text
        map.set(opt.value, opt.raw)
        $dropdown.append(option)
    })
    $dropdown.dropdown()
    $dropdown.dropdown('clear')
    return $dropdown
}

function rebuildScaProjectDropdown(projectOptions) {
    $scaSaveScanProjectDropdown = rebuildScaDropdown($scaSaveScanProjectDropdown, scaSaveScanProjectMap, projectOptions, 'Select a project')
}

function rebuildScaDownloadProjectDropdown(projectOptions) {
    $scaDownloadProjectDropdown = rebuildScaDropdown($scaDownloadProjectDropdown, scaDownloadProjectMap, projectOptions, 'Select a project')
    if (!$scaDownloadProjectDropdown) return
    $scaDownloadProjectDropdown.off('change').on('change', function () {
        const selected = $(this).val()
        if (!selected) {
            clearScaDownloadScansTable()
            setScaDownloadScansError('')
            return
        }
        const projectId = scaDownloadProjectMap.get(selected) ?? selected
        loadScaScansForProject(projectId)
    })
}

function hideScaSaveScanModalError() {
    $scaSaveScanModalError.hide().text('')
}

function showScaSaveScanModalError(message) {
    $scaSaveScanModalError.text(message || '').show()
}

function runScaSaveScan(projectId, $loader) {
    hideScaSaveScanModalError()
    if ($loader) {
        $loader.addClass('active')
    }
    $scaSaveScanModal.addClass('loading')
    controller.saveScan(projectId).then(result => {
        handleScaSaveScanResponse(result)
        $scaSaveScanModal.modal('hide')
    }).catch(err => {
        showScaResultModal('Error', err?.message || 'Unable to save scan')
    }).finally(() => {
        if ($loader) {
            $loader.removeClass('active')
        }
        $scaSaveScanModal.removeClass('loading')
    })
}

function showScaSaveScanModal($loader) {
    hideScaSaveScanModalError()
    $scaSaveScanModal
        .modal({
            allowMultiple: true,
            onApprove: function () {
                const projectId = $scaSaveScanProjectDropdown.val()
                if (!projectId) {
                    showScaSaveScanModalError('Select a project to continue.')
                    return false
                }
                const payloadProjectId = scaSaveScanProjectMap.get(projectId) ?? projectId
                runScaSaveScan(payloadProjectId, $loader)
                return false
            }
        })
        .modal('show')
}

function fetchScaPortalProjects() {
    return controller.getProjects().then(result => {
        if (!result?.success) {
            const message = result?.json?.message || result?.message || 'Unable to load projects. Check your PTK+ configuration.'
            throw new Error(message)
        }
        const projectOptions = buildScaProjectOptions(result.json)
        if (!projectOptions.length) {
            throw new Error('No projects available. Create a project in the portal and try again.')
        }
        return projectOptions
    })
}

function requestScaProjectsAndShowModal($loader) {
    if ($loader) {
        $loader.addClass('active')
    }
    fetchScaPortalProjects()
        .then(projectOptions => {
            rebuildScaProjectDropdown(projectOptions)
            showScaSaveScanModal($loader)
        })
        .catch(err => {
            showScaResultModal('Error', err?.message || 'Unable to load projects. Check your PTK+ configuration.')
        })
        .finally(() => {
            if ($loader) {
                $loader.removeClass('active')
            }
        })
}

function setScaDownloadScansError(message) {
    if (message) {
        $('#download_error').text(message)
        $('#download_scans_error').show()
    } else {
        $('#download_error').text('')
        $('#download_scans_error').hide()
    }
}

function extractScaDownloadScans(payload, inheritedHost = '') {
    if (!payload) return []
    if (Array.isArray(payload)) {
        return payload.reduce((acc, item) => acc.concat(extractScaDownloadScans(item, inheritedHost)), [])
    }
    if (typeof payload !== 'object') return []
    const host = payload.hostname || payload.host || payload.domain || payload.project || payload.name || inheritedHost || ''
    if (Array.isArray(payload.scans)) {
        return payload.scans.reduce((acc, item) => acc.concat(extractScaDownloadScans(item, host)), [])
    }
    const scanId = payload.scanId || payload.id
    if (scanId) {
        const rawDate = payload.scanDate || payload.finished_at || payload.created_at || payload.started_at || payload.meta?.scanDate
        return [{ hostname: host, scanId, scanDate: rawDate, raw: payload }]
    }
    const containers = ['items', 'findings', 'data', 'results', 'entries', 'projects', 'records']
    return containers.reduce((acc, key) => {
        if (!payload[key]) return acc
        return acc.concat(extractScaDownloadScans(payload[key], host))
    }, [])
}

function renderScaDownloadScansTable(items) {
    const entries = extractScaDownloadScans(items)
    const dt = []
    entries.forEach(entry => {
        if (!entry) return
        const scanId = entry.scanId || ''
        const hostname = entry.hostname || entry.raw?.meta?.hostname || ''
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
    dt.sort((a, b) => {
        if (a[0] === b[0]) return 0
        return a[0] < b[0] ? -1 : 1
    })
    const groupColumn = 0
    let params = {
        data: dt,
        columnDefs: [{
            visible: false,
            targets: groupColumn
        }],
        order: [[groupColumn, 'asc']],
        drawCallback: function () {
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
        }
    }
    bindTable('#tbl_scans', params)
}

function clearScaDownloadScansTable() {
    renderScaDownloadScansTable([])
}

function loadScaDownloadProjects() {
    setScaDownloadScansError('')
    clearScaDownloadScansTable()
    $downloadScansModal.addClass('loading')
    fetchScaPortalProjects()
        .then(options => {
            rebuildScaDownloadProjectDropdown(options)
        })
        .catch(err => {
            setScaDownloadScansError(err?.message || 'Unable to load projects. Check your PTK+ configuration.')
        })
        .finally(() => {
            $downloadScansModal.removeClass('loading')
        })
}

function loadScaScansForProject(projectId) {
    if (!projectId) {
        setScaDownloadScansError('Select a project to load scans.')
        clearScaDownloadScansTable()
        return
    }
    setScaDownloadScansError('')
    $downloadScansModal.addClass('loading')
    controller.downloadScans(projectId, 'sca').then(result => {
        if (!result?.success) {
            const message = result?.json?.message || result?.message || 'Unable to load scans.'
            setScaDownloadScansError(message)
            clearScaDownloadScansTable()
            return
        }
        setScaDownloadScansError('')
        renderScaDownloadScansTable(result.json)
    }).catch(err => {
        setScaDownloadScansError(err?.message || 'Unable to load scans.')
        clearScaDownloadScansTable()
    }).finally(() => {
        $downloadScansModal.removeClass('loading')
    })
}

function filterByRequestId(requestId) {

}

function showWelcomeForm() {
    setScaPageLoader(false)
    $('#main').hide()
    $('#welcome_message').show()
    $('#run_scan_bg_control').show()
}

function hideWelcomeForm() {
    $('#welcome_message').hide()
    $('#main').show()
}

function showRunningForm(result) {
    setScaPageLoader(false)
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
    setScaPageLoader(false)
    $('#main').show()
    $('#run_scan_bg_control').show()
}

function hideScanForm() {
    $('#run_scan_bg_control').hide()
}

function setScaPageLoader(show) {
    const $loader = $('#sca_page_loader')
    if (!$loader.length) return
    $loader.toggle(!!show)
}


function changeView(result) {
    $('#init_loader').removeClass('active')
    if (result.isScanRunning) {
        hideWelcomeForm()
        hideScanForm()
        showRunningForm(result)
    }
    else if (Array.isArray(result.scanResult?.findings) && result.scanResult.findings.length > 0) {
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
    clearScaPanels()
    rutils.bindStats({
        attacksCount: 0,
        findingsCount: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    }, 'sca')
}


function bindScanResult(result) {
    if (!result.scanResult) return
    controller.scanResult = result.scanResult
    const flatFindings = Array.isArray(result.scanResult.findings) ? result.scanResult.findings : []
    scaComponents = buildScaComponentsFromFindings(flatFindings)
    if (selectedComponentKey) {
        const exists = scaComponents.some(component => getComponentKey(component) === selectedComponentKey)
        if (!exists) {
            selectedComponentKey = null
        }
    }
    $("#progress_message").hide()
    $('.generate_report').show()
    $('.save_scan').show()
    hideWelcomeForm()
    renderScaComponentList()
    renderScaFindings()
    $(document).trigger("bind_stats", result.scanResult)
}


function renderScaComponentList() {
    const $list = $('#sca_component_list')
    if (!$list.length) return
    if (!scaComponents.length) {
        //$list.html(buildPlaceholderHtml('plug', 'No vulnerable components yet', 'Run a scan to populate this list.'))
        $('#components_count').text(0)
        return
    }
    const html = scaComponents
        .map((item, idx) => {
            const key = getComponentKey(item)
            return rutils.bindSCAComponentItem(item, idx, { selected: selectedComponentKey && key === selectedComponentKey })
        })
        .join('')
    $list.html(html)
    const filteredCount = selectedComponentKey ? 1 : scaComponents.length
    $('#components_count').text(filteredCount)
    const encodedKey = selectedComponentKey ? encodeURIComponent(selectedComponentKey) : null
    $list.find('.sca-component-item').removeClass('active')
    $list.find('.sca-component-item .filter.icon').removeClass('primary')
    if (encodedKey) {
        const $target = $list.find(`.sca-component-item[data-component="${encodedKey}"]`)
        $target.addClass('active')
        $target.find('.filter.icon').addClass('primary')
    }
}

function renderScaFindings() {
    const $details = $('#sca_findings_info')
    if (!$details.length) return
    const entries = []
    scaComponents.forEach(component => {
        const key = getComponentKey(component)
        if (selectedComponentKey && key !== selectedComponentKey) return
        const list = Array.isArray(component.findings) ? component.findings : []
        list.forEach(finding => entries.push({ component, finding }))
    })
    if (!entries.length) {
        updateScaStatsFromEntries(entries)
        const message = selectedComponentKey ? 'No findings for this component' : 'No findings available'
        //$details.html(buildPlaceholderHtml('check circle', message))
        return
    }
    const sortedEntries = sortScaEntries(entries)
    updateScaStatsFromEntries(sortedEntries)
    const bucketMarkup = {
        critical: [],
        high: [],
        medium: [],
        low: [],
        info: []
    }
    const bucketOrder = ['critical', 'high', 'medium', 'low', 'info']
    sortedEntries.forEach((entry, idx) => {
        const bucket = getScaBucket(entry?.finding)
        bucketMarkup[bucket].push(rutils.bindSCAFinding(entry.component, entry.finding, idx))
    })
    const html = bucketOrder
        .map((bucket) => `<div class="sca_bucket${bucketMarkup[bucket].length ? ' has-items' : ''}" data-bucket="${bucket}">${bucketMarkup[bucket].join('')}</div>`)
        .join('')
    $details.html(html)
}

function selectScaComponent(componentKey) {
    const normalized = (componentKey || '').toLowerCase()
    if (normalized && normalized === selectedComponentKey) {
        selectedComponentKey = null
    } else {
        selectedComponentKey = normalized || null
    }
    renderScaComponentList()
    renderScaFindings()
}

function buildPlaceholderHtml(icon, title, subtitle = '') {
    const safeTitle = ptk_utils.escapeHtml(title || '')
    const safeSubtitle = subtitle ? `<div class="sub header">${ptk_utils.escapeHtml(subtitle)}</div>` : ''
    return `
        <div class="ui placeholder basic segment">
            <div class="ui icon header">
                <i class="${icon} icon"></i>
                ${safeTitle}
                ${safeSubtitle}
            </div>
        </div>`
}

function getScaBucket(finding) {
    const severity = String(finding?.severity || 'info').toLowerCase()
    if (severity === 'critical') return 'critical'
    if (severity === 'high') return 'high'
    if (severity === 'medium') return 'medium'
    if (severity === 'low') return 'low'
    return 'info'
}

function clearScaPanels() {
    scaComponents = []
    selectedComponentKey = null
    renderScaComponentList()
    renderScaFindings()
}

function sortScaEntries(entries) {
    const list = Array.isArray(entries) ? [...entries] : []
    switch (scaSortType) {
        case 'component':
            return list.sort((a, b) => {
                const compA = getComponentKey(a.component)
                const compB = getComponentKey(b.component)
                if (compA < compB) return -1
                if (compA > compB) return 1
                return severityRank(b.finding) - severityRank(a.finding)
            })
        case 'file':
            return list.sort((a, b) => {
                const fileA = (a.component?.file || '').toString().toLowerCase()
                const fileB = (b.component?.file || '').toString().toLowerCase()
                if (fileA < fileB) return -1
                if (fileA > fileB) return 1
                return severityRank(b.finding) - severityRank(a.finding)
            })
        case 'severity':
        default:
            return list.sort((a, b) => severityRank(b.finding) - severityRank(a.finding))
    }
}

function severityRank(finding) {
    const sev = normalizeSeverityKey(finding?.severity)
    if (sev === 'critical') return 4
    if (sev === 'high') return 3
    if (sev === 'medium') return 2
    if (sev === 'low') return 1
    return 0
}

function normalizeSeverityKey(value) {
    const normalized = String(value || '').toLowerCase()
    if (normalized === 'critical') return 'critical'
    if (normalized === 'high') return 'high'
    if (normalized === 'medium') return 'medium'
    if (normalized === 'low') return 'low'
    return 'info'
}

function getComponentKey(component) {
    const name = String(component?.component || '').toLowerCase()
    const file = String(component?.file || '').toLowerCase()
    return `${name}::${file}`
}

function updateScaStatsFromEntries(entries) {
    const stats = entries.reduce((acc, entry) => {
        const key = normalizeSeverityKey(entry?.finding?.severity)
        acc.findingsCount += 1
        acc[key] += 1
        return acc
    }, { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 })
    rutils.bindStats(stats, 'sca')
}

function buildScaComponentsFromFindings(findings = []) {
    const map = new Map()
    findings.forEach(finding => {
        const transformed = transformFindingForUi(finding)
        if (!transformed) return
        const key = transformed.key
        if (!map.has(key)) {
            map.set(key, {
                component: transformed.component,
                version: transformed.version,
                file: transformed.file,
                findings: []
            })
        }
        map.get(key).findings.push(transformed.finding)
    })
    return Array.from(map.values())
}

function transformFindingForUi(finding) {
    if (!finding || (finding.engine && finding.engine !== "SCA")) return null
    const evidence = finding.evidence?.sca || {}
    const componentInfo = evidence.component || {}
    const componentName = componentInfo.name || componentInfo.component || finding.ruleName || 'Dependency'
    const version = componentInfo.version || 'n/a'
    const file = evidence.sourceFile || finding.location?.file || null
    const key = getComponentKey({ component: componentName, file })
    const identifiers = cloneIdentifiers(evidence.identifiers)
    const summary = evidence.summary || identifiers.summary || finding.description || finding.ruleName || null
    if (summary && (!identifiers.summary || typeof identifiers.summary !== "string")) {
        identifiers.summary = summary
    }
    const versionRange = evidence.versionRange || {}
    const convertedFinding = {
        severity: finding.severity || 'medium',
        identifiers,
        info: Array.isArray(evidence.info) ? evidence.info.slice() : [],
        cwe: finding.cwe,
        atOrAbove: versionRange.atOrAbove || null,
        above: versionRange.above || null,
        atOrBelow: versionRange.atOrBelow || null,
        below: versionRange.below || null
    }
    return {
        key,
        component: componentName,
        version,
        file,
        finding: convertedFinding
    }
}

function cloneIdentifiers(raw) {
    if (!raw || typeof raw !== 'object') return {}
    try {
        return JSON.parse(JSON.stringify(raw))
    } catch (_) {
        const copy = {}
        Object.keys(raw).forEach(key => {
            copy[key] = raw[key]
        })
        return copy
    }
}




////////////////////////////////////
/* Chrome runtime events handlers */
////////////////////////////////////
browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {

})
