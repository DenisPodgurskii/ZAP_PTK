/* Author: Denis Podgurskii */
import { ptk_controller_sast } from "../../../controller/sast.js";
import { ptk_utils } from "../../../background/utils.js";
import { ptk_decoder } from "../../../background/decoder.js";
import * as rutils from "../js/rutils.js";
import { normalizeScanResult } from "../js/scanResultViewModel.js";

const controller = new ptk_controller_sast();
const decoder = new ptk_decoder();
const sastFilterState = {
  scope: "all",
  fileCanon: null,
  ruleKey: null,
};
const RULE_FILTER_ALL_VALUE = "__sast_all_rules__";
const RULE_FILTER_DROPDOWN_SELECTOR = "#rule_filter_dropdown";
let isRuleDropdownSyncing = false;
const SAST_DELTA_QUEUE = [];
const SAST_FLUSH_INTERVAL_MS = 300;
let sastFlushTimer = null;
const SAST_BUCKET_ORDER = ["critical", "high", "medium", "low", "info"];

function normalizeSastSeverityKey(value) {
  const key = String(value || "").toLowerCase();
  if (key === "critical" || key === "high" || key === "medium" || key === "low" || key === "info") {
    return key;
  }
  if (key === "informational") return "info";
  return "info";
}

function getSastBucket(item) {
  const severity = item?.metadata?.severity || item?.severity || "";
  return normalizeSastSeverityKey(severity);
}

function buildSastBucketHtml() {
  return SAST_BUCKET_ORDER
    .map((bucket) => `<div class="sast_bucket" data-bucket="${bucket}"></div>`)
    .join("");
}

function ensureSastBuckets() {
  const $container = $("#attacks_info");
  if ($container.find(".sast_bucket").length) return;
  $container.html(buildSastBucketHtml());
}

function appendSastToBucket(attackHtml, bucketKey) {
  if (!attackHtml) return;
  ensureSastBuckets();
  const selector = `.sast_bucket[data-bucket="${bucketKey}"]`;
  const $bucket = $("#attacks_info").find(selector);
  $bucket.addClass("has-items");
  $bucket.append(attackHtml);
}

function hasRenderableSastData(scanResult) {
  if (!scanResult) return false;
  if (Array.isArray(scanResult.findings) && scanResult.findings.length) return true;
  const items = scanResult.items;
  if (Array.isArray(items) && items.length) return true;
  if (items && typeof items === "object" && Object.keys(items).length) return true;
  return false;
}

function normalizeLegacySastItems(items) {
  if (Array.isArray(items)) return items;
  if (items && typeof items === "object") {
    return Object.keys(items)
      .sort()
      .map((key) => items[key])
      .filter(Boolean);
  }
  return [];
}

function formatSeverityLabel(value) {
  if (!value) return "Info";
  const lower = String(value).toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

function buildSastItemFromFinding(finding, index) {
  if (!finding) return null;
  const loc = finding.location || {};
  const ev = (finding.evidence && finding.evidence.sast) || {};
  const severity = formatSeverityLabel(finding.severity);
  const owaspArray = Array.isArray(finding.owasp) ? finding.owasp : [];
  const owaspPrimary = finding.owaspPrimary || (owaspArray.length ? owaspArray[0] : null);
  const owaspLegacy = finding.owaspLegacy || (owaspPrimary ? `${owaspPrimary.id}:${owaspPrimary.version}-${owaspPrimary.name}` : "");
  const ruleId = finding.ruleId || finding.id || `rule-${index}`;
  const description = finding.description || ev.description || "";
  const recommendation = finding.recommendation || ev.recommendation || "";
  const metadata = {
    id: ruleId,
    rule_id: ruleId,
    name: finding.ruleName || finding.moduleName || ruleId,
    severity,
    description,
    recommendation,
  };
  const moduleMeta = {
    id: finding.moduleId || null,
    name: finding.moduleName || null,
    severity,
    category: finding.category || null,
    owasp: owaspArray,
    owaspPrimary,
    owaspLegacy,
    cwe: finding.cwe || null,
    tags: finding.tags || [],
    links: finding.links || {},
  };
  const sourceRaw = ev.source || {};
  const sinkRaw = ev.sink || {};
  const source = Object.assign(
    {
      sourceName: sourceRaw.sourceName || sourceRaw.label || "Source",
      label: sourceRaw.label || sourceRaw.sourceName || "Source",
      sourceFile: sourceRaw.sourceFile || loc.file || "",
      sourceFileFull: sourceRaw.sourceFileFull || sourceRaw.sourceFile || loc.file || "",
      sourceLoc: sourceRaw.sourceLoc || null,
      sourceSnippet: sourceRaw.sourceSnippet || ev.codeSnippet || "",
    },
    sourceRaw
  );
  const sink = Object.assign(
    {
      sinkName: sinkRaw.sinkName || sinkRaw.label || "Sink",
      label: sinkRaw.label || sinkRaw.sinkName || "Sink",
      sinkFile: sinkRaw.sinkFile || loc.file || "",
      sinkFileFull: sinkRaw.sinkFileFull || sinkRaw.sinkFile || loc.file || "",
      sinkLoc: sinkRaw.sinkLoc || null,
      sinkSnippet: sinkRaw.sinkSnippet || "",
    },
    sinkRaw
  );
  return {
    codeFile: loc.file || sink.sinkFile || source.sourceFile || null,
    codeSnippet: ev.codeSnippet || "",
    pageUrl: loc.pageUrl || loc.url || null,
    pageCanon: loc.pageUrl || loc.url || null,
    metadata,
    module_metadata: moduleMeta,
    owasp: owaspArray,
    owaspPrimary,
    owaspLegacy,
    source,
    sink,
    trace: ev.trace || finding.trace || [],
    nodeType: ev.nodeType || finding.nodeType || null,
    confidence: Number.isFinite(finding.confidence) ? finding.confidence : null,
    requestId: index,
    type: "sast",
  };
}

function getSastAttackItem(index) {
  if (Number.isNaN(Number(index))) return null;
  const items = Array.isArray(controller?.sastAttackItems)
    ? controller.sastAttackItems
    : null;
  if (items && items[index]) {
    return items[index];
  }
  const legacyItems = controller?.scanResult?.scanResult?.items;
  if (!legacyItems) return null;
  if (Array.isArray(legacyItems)) return legacyItems[index] || null;
  if (typeof legacyItems === "object") {
    const values = normalizeLegacySastItems(legacyItems);
    return values[index] || null;
  }
  return null;
}

function extractSastFindingsForStats(raw, vm) {
  if (Array.isArray(vm?.findings) && vm.findings.length) return vm.findings;
  if (Array.isArray(raw?.findings) && raw.findings.length) return raw.findings;
  if (raw?.items) return normalizeLegacySastItems(raw.items);
  return [];
}

function summarizeSastFindings(findings) {
  const summary = {
    findingsCount: 0,
    rulesCount: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  if (!Array.isArray(findings) || !findings.length) {
    return summary;
  }
  const rules = new Set();
  findings.forEach((finding) => {
    if (!finding) return;
    summary.findingsCount += 1;
    const severity = String(finding?.severity || finding?.metadata?.severity || "").toLowerCase();
    if (severity === "critical") summary.critical += 1;
    else if (severity === "high") summary.high += 1;
    else if (severity === "medium") summary.medium += 1;
    else if (severity === "low") summary.low += 1;
    else summary.info += 1;
    const candidates = [
      finding?.ruleId,
      finding?.rule_id,
      finding?.id,
      finding?.metadata?.id,
      finding?.module_metadata?.id,
    ];
    const id = candidates.find((value) => value !== undefined && value !== null && String(value).trim());
    if (id) {
      rules.add(String(id).trim());
    }
  });
  summary.rulesCount = rules.size;
  return summary;
}

function triggerSastStatsEvent(rawScanResult, viewModel) {
  const raw = rawScanResult || {};
  const vm = viewModel || normalizeScanResult(raw);
  const derived = summarizeSastFindings(extractSastFindingsForStats(raw, vm));
  const stats = Object.assign({}, derived, vm.stats || raw.stats || {});
  $(document).trigger("bind_stats", Object.assign({}, raw, { stats }));
}

jQuery(function () {
  // initialize all modals
  $(".modal.coupled").modal({
    allowMultiple: true,
  });

  $(document).on("click", ".showHtml", function () {
    rutils.showHtml($(this));
  });
  $(document).on("click", ".showHtmlNew", function () {
    rutils.showHtml($(this), true);
  });

  const $sastSaveScanModal = $('#sast_save_scan_modal')
  let $sastSaveScanProjectDropdown = $('#sast_save_scan_project_select')
  const $sastSaveScanModalError = $('#sast_save_scan_modal_error')
  const sastSaveScanProjectMap = new Map()
  const $downloadScansModal = $('#download_scans')
  let $sastDownloadProjectDropdown = $('#download_project_select')
  const sastDownloadProjectMap = new Map()

  function showSastResultModal(header, message) {
    $('#result_header').text(header)
    $('#result_message').text(message || '')
    $('#result_dialog').modal('show')
  }

  function handleSastSaveScanResponse(result) {
    if (result instanceof Error) {
      showSastResultModal('Error', result.message || 'Unable to save scan')
      return
    }
    if (result?.success) {
      showSastResultModal('Success', 'Scan saved')
    } else {
      const message = result?.json?.message || result?.message || 'Unable to save scan'
      showSastResultModal('Error', message)
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

  function rebuildProjectDropdown($dropdown, projectMap, projectOptions, placeholderText) {
    projectMap.clear()
    if (!$dropdown || !$dropdown.length) return $dropdown
    try {
      $dropdown.dropdown('destroy')
    } catch (err) { }
    $dropdown = resetSemanticDropdown($dropdown)
    if (!$dropdown) return $dropdown
    const placeholder = document.createElement('option')
    placeholder.value = ''
    placeholder.textContent = placeholderText || 'Select a project'
    $dropdown.append(placeholder)
    projectOptions.forEach(opt => {
      const option = document.createElement('option')
      option.value = opt.value
      option.textContent = opt.text
      projectMap.set(opt.value, opt.raw)
      $dropdown.append(option)
    })
    $dropdown.dropdown()
    $dropdown.dropdown('clear')
    return $dropdown
  }

  function rebuildSastProjectDropdown(projectOptions) {
    $sastSaveScanProjectDropdown = rebuildProjectDropdown($sastSaveScanProjectDropdown, sastSaveScanProjectMap, projectOptions, 'Select a project')
  }

  function rebuildSastDownloadProjectDropdown(projectOptions) {
    $sastDownloadProjectDropdown = rebuildProjectDropdown($sastDownloadProjectDropdown, sastDownloadProjectMap, projectOptions, 'Select a project')
    if (!$sastDownloadProjectDropdown) return
    $sastDownloadProjectDropdown.off('change').on('change', function () {
      const selected = $(this).val()
      if (!selected) {
        clearDownloadScansTable()
        setDownloadScansError('')
        return
      }
      const projectId = sastDownloadProjectMap.get(selected) ?? selected
      loadSastScansForProject(projectId)
    })
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

  function hideSastSaveScanModalError() {
    $sastSaveScanModalError.hide().text('')
  }

  function showSastSaveScanModalError(message) {
    $sastSaveScanModalError.text(message || '').show()
  }

  function runSastSaveScan(projectId, $loader) {
    hideSastSaveScanModalError()
    if ($loader) {
      $loader.addClass('active')
    }
    $sastSaveScanModal.addClass('loading')
    controller.saveScan(projectId).then(result => {
      handleSastSaveScanResponse(result)
      $sastSaveScanModal.modal('hide')
    }).catch(err => {
      showSastResultModal('Error', err?.message || 'Unable to save scan')
    }).finally(() => {
      if ($loader) {
        $loader.removeClass('active')
      }
      $sastSaveScanModal.removeClass('loading')
    })
  }

  function showSastSaveScanModal($loader) {
    hideSastSaveScanModalError()
    $sastSaveScanModal
      .modal({
        allowMultiple: true,
        onApprove: function () {
          const projectId = $sastSaveScanProjectDropdown.val()
          if (!projectId) {
            showSastSaveScanModalError('Select a project to continue.')
            return false
          }
          const payloadProjectId = sastSaveScanProjectMap.get(projectId) ?? projectId
          runSastSaveScan(payloadProjectId, $loader)
          return false
        }
      })
      .modal('show')
  }

  function fetchSastPortalProjects() {
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

  function requestSastProjectsAndShowModal($loader) {
    if ($loader) {
      $loader.addClass('active')
    }
    fetchSastPortalProjects()
      .then(projectOptions => {
        rebuildSastProjectDropdown(projectOptions)
        showSastSaveScanModal($loader)
      })
      .catch(err => {
        showSastResultModal('Error', err?.message || 'Unable to load projects. Check your PTK+ configuration.')
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

    dt.sort(function (a, b) {
      if (a[0] === b[0]) {
        return 0
      } else {
        return a[0] < b[0] ? -1 : 1
      }
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

  function loadSastDownloadProjects() {
    setDownloadScansError('')
    clearDownloadScansTable()
    $downloadScansModal.addClass('loading')
    fetchSastPortalProjects()
      .then(options => {
        rebuildSastDownloadProjectDropdown(options)
      })
      .catch(err => {
        setDownloadScansError(err?.message || 'Unable to load projects. Check your PTK+ configuration.')
      })
      .finally(() => {
        $downloadScansModal.removeClass('loading')
      })
  }

  function loadSastScansForProject(projectId) {
    if (!projectId) {
      setDownloadScansError('Select a project to load scans.')
      clearDownloadScansTable()
      return
    }
    setDownloadScansError('')
    $downloadScansModal.addClass('loading')
    controller.downloadScans(projectId, 'sast').then(result => {
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

  $(document).on("click", ".generate_report", function () {
    browser.windows.create({
      type: "popup",
      url: browser.runtime.getURL("/ptk/browser/report.html?sast_report"),
    });
  });

  $(document).on("click", ".save_scan", function () {
    const $loader = $(this).find('.loader')
    requestSastProjectsAndShowModal($loader)
  });

  $(document).on("click", ".run_scan_runtime", function () {
    controller
      .init()
      .then(async function (result) {
        if (!result?.activeTab?.url) {
          $("#result_header").text("Error");
          $("#result_message").text(
            "Active tab not set. Reload required tab to activate tracking."
          );
          $("#result_dialog").modal("show");
          return false;
        }

        let h = new URL(result.activeTab.url).host;
        $("#scan_host").text(h);
        // $('#scan_domains').text(h)
        window._ptkSastReloadWarningClosed = false;
        let contentReady = true;
        contentReady = await rutils.pingContentScript(result.activeTab.tabId, { timeoutMs: 700 });
        if (!window._ptkSastReloadWarningClosed) {
          $("#ptk_scan_reload_warning").toggle(!contentReady);
        }

        $("#run_scan_dlg")
          .modal({
            allowMultiple: true,
            onApprove: function () {
              if (!contentReady) {
                $("#ptk_scan_reload_warning").show();
                return false;
              }
              let scanStrategy = $("#sast-scan-strategy").val();
              if (scanStrategy === undefined || scanStrategy === null || scanStrategy === '') {
                scanStrategy = 0;
              }
              const pagesRaw = $("#sast_pages").val() || "";
              const pages = String(pagesRaw)
                .split(/[\n,]+/)
                .map((entry) => entry.trim())
                .filter(Boolean);
              controller
                .runBackgroundScan(result.activeTab.tabId, h, scanStrategy, pages)
                .then(function (result) {
                  $("#request_info").html("");
                  $("#attacks_info").html("");
                  triggerSastStatsEvent(result.scanResult);
                  changeView(result);
                }).catch(e => e)
            },
          })
          .modal("show");
        $('#sast_scans_form .question')
          .popup({
            inline: true,
            hoverable: true,
            delay: {
              show: 300,
              hide: 800
            }
          })
      })
      .catch((e) => e);

    return false;
  });

  $(document).on("click", "#ptk_scan_reload_warning_close_sast", function () {
    window._ptkSastReloadWarningClosed = true;
    $("#ptk_scan_reload_warning").hide();
  });

  $(document).on("click", ".stop_scan_runtime", function () {
    controller.stopBackgroundScan().then(function (result) {
      changeView(result);
      bindScanResult(result);
    }).catch(e => e)
    return false;
  });

  $(".settings.rattacker").on("click", function () {
    $("#settings").modal("show");
  });

  $(".cloud_download_scans").on("click", function () {
    $downloadScansModal.modal("show");
    loadSastDownloadProjects();
  });

  $(document).on("click", ".download_scan_by_id", function () {
    $(this).parent().find(".loader").addClass("active");
    let scanId = $(this).attr("data-scan-id");
    controller.downloadScanById(scanId).then(function (result) {
      if (result?.success === false) {
        const message = result?.json?.message || result?.message || 'Unable to download scan'
        showSastResultModal('Error', message)
        return
      }
      let info = { isScanRunning: false, scanResult: result };
      changeView(info);
      if (hasRenderableSastData(info.scanResult)) {
        bindScanResult(info);
      }
      $("#download_scans").modal("hide");
    }).catch(err => {
      showSastResultModal('Error', err?.message || 'Unable to download scan')
    });
  });

  $(".import_export").on("click", function () {
    controller.init().then(function (result) {
      if (!hasRenderableSastData(result.scanResult)) {
        $(".export_scan_btn").addClass("disabled");
      } else {
        $(".export_scan_btn").removeClass("disabled");
      }
      $("#import_export_dlg").modal("show");
    }).catch(e => e)
  });

  $(".export_scan_btn").on("click", function () {
    controller.exportScanResult().then(function (scanResult) {
      if (scanResult && hasRenderableSastData(scanResult)) {
        let blob = new Blob([JSON.stringify(scanResult)], {
          type: "text/plain",
        });
        let fName = "PTK_SAST_scan.json";

        let downloadLink = document.createElement("a");
        downloadLink.download = fName;
        downloadLink.innerHTML = "Download File";
        downloadLink.href = window.URL.createObjectURL(blob);
        downloadLink.click();
      } else {
        showSastResultModal('Error', 'Nothing to export yet.')
      }
    }).catch(err => {
      showSastResultModal('Error', err?.message || 'Unable to export scan')
    });
  });

  $(".import_scan_file_btn").on("click", function (e) {
    $("#import_scan_file_input").trigger("click");
    e.stopPropagation();
    e.preventDefault();
  });

  $("#import_scan_file_input").on("change", function (e) {
    e.stopPropagation();
    e.preventDefault();
    let file = $("#import_scan_file_input").prop("files")[0];
    loadFile(file);
    $("#import_scan_file_input").val(null);
  });

  async function loadFile(file) {
    var fileReader = new FileReader();
    fileReader.onload = function () {
      controller
        .save(fileReader.result)
        .then((result) => {
          changeView(result);
          if (hasRenderableSastData(result.scanResult)) {
            bindScanResult(result);
          }
          $("#import_export_dlg").modal("hide");
        })
        .catch((e) => {
          $("#result_message").text("Could not import SAST scan");
          $("#result_dialog").modal("show");
        });
    };

    fileReader.onprogress = (event) => {
      if (event.lengthComputable) {
      }
    };
    fileReader.readAsText(file);
  }

  $(".import_scan_text_btn").on("click", function () {
    let scan = $("#import_scan_json").val();
    controller
      .save(scan)
      .then((result) => {
        changeView(result);
        if (hasRenderableSastData(result.scanResult)) {
          bindScanResult(result);
        }
        $("#import_export_dlg").modal("hide");
      })
      .catch((e) => {
        $("#result_message").text("Could not import SAST scan");
        $("#result_dialog").modal("show");
      });
  });

  $(document).on("click", ".delete_scan_by_id", function () {
    let scanId = $(this).attr("data-scan-id");
    let scanHost = $(this).attr("data-scan-host");
    $("#scan_hostname").val("");
    $("#scan_delete_message").text("");
    $("#delete_scan_dlg")
      .modal({
        allowMultiple: true,
        onApprove: function () {
          if ($("#scan_hostname").val() == scanHost) {
            return controller.deleteScanById(scanId).then(function (result) {
              $(".cloud_download_scans").trigger("click");
              //console.log(result)
              return true;
            });
          } else {
            $("#scan_delete_message").text(
              "Type scan hostname to confirm delete"
            );
            return false;
          }
        },
      })
      .modal("show");
  });

  $(document).on("click", ".reset", function () {
    $("#request_info").html("");
    $("#attacks_info").html("");
    clearSastRequestFilter();
    $(".generate_report").hide();
    $(".save_scan").hide();
    //$('.exchange').hide()

    hideRunningForm();
    showWelcomeForm();
    controller.reset().then(function (result) {
      triggerSastStatsEvent(result.scanResult);
      if (Array.isArray(result?.default_modules) && result.default_modules.length) {
        bindModules(result);
      }
    });
  });

  $(".send_rbuilder").on("click", function () {
    let request = $("#raw_request").val().trim();
    window.location.href =
      "rbuilder.html?rawRequest=" +
      decoder.base64_encode(encodeURIComponent(JSON.stringify(request)));
    return false;
  });

  $("#filter_all").on("click", function () {
    setSastScopeFilter("all");
  });

  $("#filter_vuln").on("click", function () {
    setSastScopeFilter("vuln");
  });

  $(document).on("click", "#request_info .filter.icon", function (e) {
    e.stopPropagation();
    const file = $(this).closest(".title.short_message_text").attr("data-file");
    toggleSastRequestFilter(file);
  });

  $(document).on("click", "#request_info .title.short_message_text", function (e) {
    if ($(e.target).closest(".filter.icon").length) {
      return;
    }
    const file = $(this).attr("data-file");
    toggleSastRequestFilter(file);
  });
  setSastScopeFilter("all");
  initRuleFilterDropdown();

  $(document).on("click", ".btn_stacktrace", function () {
    let el = $(this).parent().find(".content.stacktrace");
    if (this.textContent.trim().startsWith('Show')) {
      this.textContent = "Hide";
      $(el).show();
    } else {
      $(this).parent().find(".content.stacktrace").hide();
      this.textContent = "Show code and recommendation";
    }
  });

  $(document).on("click", ".close.icon.stacktrace", function () {
    $(this).parent().hide();
    $(this).parent().parent().find(".btn_stacktrace").text("Show code and recommendation");
  });

  $(document).on("click", ".sast-trace-toggle", function (e) {
    e.preventDefault();
    const $toggle = $(this);
    let $wrapper = $toggle.closest(".sast-trace");
    if (!$wrapper.length) {
      $wrapper = $toggle.nextAll(".sast-trace").first();
    }
    if (!$wrapper.length) return;
    const expanded = $wrapper.attr("data-expanded") === "true";
    const next = !expanded;
    $wrapper.attr("data-expanded", next ? "true" : "false");
    $toggle.text(next ? "Hide full trace" : "Show full trace");
    $toggle.attr("aria-expanded", next ? "true" : "false");
  });

  $(document).on("bind_stats", function (e, scanResult) {
    if (scanResult?.stats) {
      rutils.bindStats(scanResult.stats, "sast");
      if ((scanResult.stats.findingsCount || 0) > 0) {
        $("#filter_vuln").trigger("click");
      }
    }
    return false;
  });

  $.fn.selectRange = function (start, end) {
    var e = document.getElementById($(this).attr("id")); // I don't know why... but $(this) don't want to work today :-/
    if (!e) return;
    else if (e.setSelectionRange) {
      e.focus();
      e.setSelectionRange(start, end);
    } /* WebKit */ else if (e.createTextRange) {
      var range = e.createTextRange();
      range.collapse(true);
      range.moveEnd("character", end);
      range.moveStart("character", start);
      range.select();
    } /* IE */ else if (e.selectionStart) {
      e.selectionStart = start;
      e.selectionEnd = end;
    }
  };

  controller.init().then(function (result) {
    const initCount = Array.isArray(result?.scanResult?.findings) ? result.scanResult.findings.length : 0;
    changeView(result);
    if (result.isScanRunning) {
      showRunningForm(result);
      if (hasRenderableSastData(result.scanResult)) {
        bindScanResult(result);
      }
    } else if (hasRenderableSastData(result.scanResult)) {
      bindScanResult(result);
    } else if (Array.isArray(result?.default_modules) && result.default_modules.length) {
      bindModules(result);
      showWelcomeForm();
    } else {
      showWelcomeForm();
    }
  }).catch(() => { })
});

function showWelcomeForm() {
  setSastPageLoader(false);
  $("#main").hide();
  $("#welcome_message").show();
  $("#run_scan_bg_control").show();
}

function hideWelcomeForm() {
  $("#welcome_message").hide();
  $("#main").show();
}

function showRunningForm(result) {
  setSastPageLoader(false);
  $("#main").show();
  $("#scanning_url").text(result.scanResult.host);
  $(".scan_info").show();
  $("#stop_scan_bg_control").show();
}

function hideRunningForm() {
  $("#scanning_url").text("");
  $(".scan_info").hide();
  $("#stop_scan_bg_control").hide();
}

function showScanForm(result) {
  setSastPageLoader(false);
  $("#main").show();
  $("#run_scan_bg_control").show();
}

function hideScanForm() {
  $("#run_scan_bg_control").hide();
}

function setSastPageLoader(show) {
  const $loader = $("#sast_page_loader");
  if (!$loader.length) return;
  $loader.toggle(!!show);
}

function changeView(result) {
  $("#init_loader").removeClass("active");
  if (result.isScanRunning) {
    hideWelcomeForm();
    hideScanForm();
    showRunningForm(result);
  } else if (hasRenderableSastData(result.scanResult)) {
    hideWelcomeForm();
    hideRunningForm(result);
    showScanForm();
  } else {
    hideRunningForm();
    hideScanForm();
    showWelcomeForm();
  }
}

$(document).on("click", ".attack_details", function () {
  $('.metadata .item').tab()
  const indexAttr = $(this).attr("data-index")
  const index = typeof indexAttr !== "undefined" ? Number(indexAttr) : NaN
  const attack = getSastAttackItem(index)
  if (!attack) return
  rutils.bindAttackDetails_SAST($(this), attack)
  $('.metadata .item').tab('change tab', 'first');
})

function bindRequest(info) {
  const raw = info === undefined || info === null ? "" : String(info);
  const escapedRaw = ptk_utils.escapeHtml(raw);
  const canon = typeof rutils?.canonicalizeSastFileId === "function"
    ? rutils.canonicalizeSastFileId(raw)
    : raw;
  const escapedCanon = ptk_utils.escapeHtml(canon || "");
  let item = `
                <div>
                <div class="title short_message_text" data-file="${escapedRaw}" data-file-canon="${escapedCanon}" style="overflow-y: hidden;height: 34px;background-color: #eeeeee;margin:1px 0 0 0;cursor:pointer; position: relative">
                    ${escapedRaw}<i class="filter icon" style="float:right; position: absolute; top: 3px; right: -3px;" title="Filter by request"></i>
                    
                </div>
                `
  return item
}

function bindScanResult(result) {
  if (!result.scanResult) return;
  const raw = result.scanResult || {};
  const vm = raw.__normalized ? raw : normalizeScanResult(raw);
  controller.scanResult = result;
  controller.scanViewModel = vm;
  $("#progress_message").hide();
  $(".generate_report").show();
  $(".save_scan").show();
  $("#request_info").html("");
  $("#attacks_info").html("");
  hideWelcomeForm();
  SAST_DELTA_QUEUE.length = 0;
  if (sastFlushTimer) {
    clearTimeout(sastFlushTimer);
    sastFlushTimer = null;
  }
  controller._sastKnownFilesCanon = new Set();
  controller._sastKnownRuleIds = new Set();
  controller._sastRuleCounts = new Map();

  const findings = Array.isArray(vm.findings) ? vm.findings : [];
  const legacyItems = normalizeLegacySastItems(raw.items);
  let files = Array.isArray(raw.files) ? raw.files.slice() : [];
  if (findings.length) {
    const fileCandidates = findings
      .map((finding) => finding?.location?.file)
      .filter(Boolean);
    files = files.concat(fileCandidates);
  } else if (!files.length && legacyItems.length) {
    files = legacyItems
      .map((item) => item?.codeFile || item?.file || null)
      .filter(Boolean);
  }
  files = files
    .filter((item, i, ar) => ar.indexOf(item) === i)
    .filter((item) => item && !/^inline/i.test(item));

  const requestMarkup = [];
  files.forEach((file) => {
    if (!file) return;
    const canon = typeof rutils?.canonicalizeSastFileId === "function"
      ? rutils.canonicalizeSastFileId(file)
      : file;
    if (canon) controller._sastKnownFilesCanon.add(canon);
    requestMarkup.push(bindRequest(file));
  });
  $("#request_info").html(requestMarkup.join(""));

  let attackItems = [];
  if (findings.length) {
    attackItems = findings
      .map((finding, index) => buildSastItemFromFinding(finding, index))
      .filter(Boolean);
  } else if (legacyItems.length) {
    attackItems = legacyItems.map((item, index) => {
      if (item) {
        item.requestId = index;
      }
      return item;
    }).filter(Boolean);
  }
  controller.sastAttackItems = attackItems;

  const bucketMarkup = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: []
  };
  attackItems.forEach((item, index) => {
    if (!item) return;
    const attackHtml = rutils.bindSASTAttack(item, index);
    const bucket = getSastBucket(item);
    bucketMarkup[bucket].push(attackHtml);
  });
  $("#attacks_info").html([
    `<div class="sast_bucket${bucketMarkup.critical.length ? " has-items" : ""}" data-bucket="critical">${bucketMarkup.critical.join("")}</div>`,
    `<div class="sast_bucket${bucketMarkup.high.length ? " has-items" : ""}" data-bucket="high">${bucketMarkup.high.join("")}</div>`,
    `<div class="sast_bucket${bucketMarkup.medium.length ? " has-items" : ""}" data-bucket="medium">${bucketMarkup.medium.join("")}</div>`,
    `<div class="sast_bucket${bucketMarkup.low.length ? " has-items" : ""}" data-bucket="low">${bucketMarkup.low.join("")}</div>`,
    `<div class="sast_bucket${bucketMarkup.info.length ? " has-items" : ""}" data-bucket="info">${bucketMarkup.info.join("")}</div>`
  ].join(""));

  const deferWork = () => {
    const scanning = typeof result.isScanRunning === "boolean"
      ? result.isScanRunning
      : !!controller._sastIsScanning;
    controller._sastIsScanning = scanning;
    // Keep bucket ordering; avoid DOM re-sorts.
    if (findings.length) {
      populateSastRuleFilterOptionsFromFindings(findings);
    } else {
      populateSastRuleFilterOptions(attackItems);
    }
    triggerSastStatsEvent(raw, vm);
    refreshSastFiltersAfterRender();
  };
  if (typeof requestAnimationFrame === "function") {
    requestAnimationFrame(deferWork);
  } else {
    setTimeout(deferWork, 0);
  }
}

function bindModules(result) {
  const modules = Array.isArray(result?.default_modules)
    ? result.default_modules
    : (Array.isArray(result) ? result : []);
  const rows = [];
  modules.forEach((mod) => {
    if (!mod) return;
    const moduleName = mod.name || mod.metadata?.name || mod.metadata?.module_name || mod.id || "Module";
    const defaultSeverity = formatSeverityLabel(mod.metadata?.severity);
    const rules = Array.isArray(mod.rules) ? mod.rules : [];
    if (rules.length) {
      rules.forEach((rule) => {
        const ruleName = rule?.name || rule?.metadata?.name || rule?.id || "Rule";
        const severity = formatSeverityLabel(rule?.severity || rule?.metadata?.severity || defaultSeverity || "info");
        rows.push([ruleName, moduleName, severity]);
      });
    } else {
      rows.push([moduleName, moduleName, defaultSeverity]);
    }
  });
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  rows.sort((a, b) => {
    const leftSeverity = String(a[2] || "").toLowerCase();
    const rightSeverity = String(b[2] || "").toLowerCase();
    const severityDiff =
      (severityOrder[leftSeverity] ?? 99) - (severityOrder[rightSeverity] ?? 99);
    if (severityDiff !== 0) return severityDiff;
    const nameLeft = (a[0] || "").toLowerCase();
    const nameRight = (b[0] || "").toLowerCase();
    return nameLeft.localeCompare(nameRight);
  });
  bindTable("#sast_rules_table", { data: rows });
}

function bindAttackProgress(message) {
  $("#progress_attack_name").text(message.info.message + " : " + message.info.file)
  $("#progress_message").show()
}

function applySastFindingsDelta(message) {
  const findings = Array.isArray(message?.findings) ? message.findings : [];
  if (!findings.length) return;
  if (!controller.scanViewModel) {
    if (message?.scanResult) {
      bindScanResult({ scanResult: message.scanResult });
    }
    return;
  }
  if (!Array.isArray(controller.scanViewModel.findings)) {
    controller.scanViewModel.findings = [];
  }
  if (!Array.isArray(controller.sastAttackItems)) {
    controller.sastAttackItems = [];
  }
  controller._sastIsScanning = typeof message?.isScanRunning === "boolean"
    ? message.isScanRunning
    : controller._sastIsScanning;
  findings.forEach((finding) => {
    if (!finding) return;
    SAST_DELTA_QUEUE.push(finding);
  });
  if (!sastFlushTimer) {
    sastFlushTimer = setTimeout(flushSastQueue, SAST_FLUSH_INTERVAL_MS);
  }
  if (message?.stats) {
    rutils.bindStats(message.stats, "sast");
  }
}

function incrementSastRuleOption(finding) {
  if (!finding) return;
  const rawId = finding.ruleId || finding.id || "";
  if (!rawId) return;
  const key = encodeURIComponent(rawId);
  if (!controller._sastRuleCounts) controller._sastRuleCounts = new Map();
  const existing = controller._sastRuleCounts.get(key);
  const label = existing?.label || finding.ruleName || finding.moduleName || rawId;
  const nextCount = (existing?.count || 0) + 1;
  controller._sastRuleCounts.set(key, { label, count: nextCount });
  if (!controller._sastKnownRuleIds) controller._sastKnownRuleIds = new Set();
  controller._sastKnownRuleIds.add(key);

  const $dropdown = getRuleFilterDropdown();
  if (!$dropdown.length) return;
  const $item = $dropdown.find(`.menu .item[data-value="${key}"]`);
  if ($item.length) {
    const $desc = $item.find(".description");
    if ($desc.length) {
      $desc.text(String(nextCount));
    } else {
      $item.prepend(`<span class="description">${ptk_utils.escapeHtml(String(nextCount))}</span>`);
    }
  } else {
    $dropdown.find(".menu").append(
      `<div class="item" data-value="${key}"><span class="description">${ptk_utils.escapeHtml(
        String(nextCount)
      )}</span>${ptk_utils.escapeHtml(label)}</div>`
    );
  }
  $dropdown.dropdown("refresh");
  $dropdown.toggleClass("disabled", false);
}

function flushSastQueue() {
  sastFlushTimer = null;
  if (!SAST_DELTA_QUEUE.length) return;
  const batch = SAST_DELTA_QUEUE.splice(0, SAST_DELTA_QUEUE.length);
  const attackMarkup = [];
  const requestMarkup = [];
  const knownFiles = controller._sastKnownFilesCanon || new Set();

  batch.forEach((finding) => {
    if (!finding) return;
    controller.scanViewModel.findings.push(finding);
    const file = finding?.location?.file || finding?.pageUrl || null;
    if (file) {
      const canon = typeof rutils?.canonicalizeSastFileId === "function"
        ? rutils.canonicalizeSastFileId(file)
        : file;
      if (canon && !knownFiles.has(canon)) {
        knownFiles.add(canon);
        requestMarkup.push(bindRequest(file));
      }
    }
    const index = controller.sastAttackItems.length;
    const item = buildSastItemFromFinding(finding, index);
    if (!item) return;
    controller.sastAttackItems.push(item);
    const attackHtml = rutils.bindSASTAttack(item, index);
    const bucket = getSastBucket(item);
    attackMarkup.push({ html: attackHtml, bucket });
    incrementSastRuleOption(finding);
  });

  controller._sastKnownFilesCanon = knownFiles;
  if (requestMarkup.length) {
    $("#request_info").append(requestMarkup.join(""));
  }
  if (attackMarkup.length) {
    ensureSastBuckets();
    attackMarkup.forEach(({ html, bucket }) => {
      appendSastToBucket(html, bucket);
    });
  }
}

function handleStructuredSastMessage(type, payload, scanResult) {
  const data = payload || {};
  if (type === "scan:start") {
    bindAttackProgress({ info: { message: "Scan started", file: data.totalFiles || "" } });
    controller._sastIsScanning = true;
    showRunningForm({ scanResult: controller.scanResult?.scanResult || { host: data.host || "" } });
    hideScanForm();
    hideWelcomeForm();
  }
  if (type === "file:start") {
    bindAttackProgress({ info: { message: "Scanning file", file: data.file || "" } });
  }
  if (type === "file:end") {
    bindAttackProgress({ info: { message: "Finished file", file: data.file || "" } });
  }
  if (type === "module:start") {
    bindAttackProgress({ info: { message: "Module", file: data.moduleName || data.moduleId || "" } });
  }
  if (type === "scan:summary") {
    bindAttackProgress({ info: { message: "Scan summary", file: (data.totalFindings || 0) + " findings" } });
    controller._sastIsScanning = false;
  }
  if (type === "scan:error") {
    bindAttackProgress({ info: { message: "Scan error", file: data.error || "" } });
  }
  if (scanResult) {
    bindScanResult({ scanResult: scanResult, isScanRunning: controller._sastIsScanning });
  }
}

function canonicalizeRequestFilterValue(raw) {
  if (raw === undefined || raw === null) return "";
  const value = String(raw);
  if (typeof rutils?.canonicalizeSastFileId === "function") {
    return rutils.canonicalizeSastFileId(value);
  }
  return value.trim();
}

function toggleSastRequestFilter(raw) {
  const canon = canonicalizeRequestFilterValue(raw);
  if (!canon) {
    clearSastRequestFilter();
    return;
  }
  if (sastFilterState.fileCanon === canon) {
    clearSastRequestFilter();
    return;
  }
  sastFilterState.fileCanon = canon;
  updateRequestFilterUI();
  applySastFilters();
}

function clearSastRequestFilter() {
  sastFilterState.fileCanon = null;
  updateRequestFilterUI();
  applySastFilters();
}

function setSastRuleFilter(ruleKey, syncDropdown = true) {
  const normalized =
    ruleKey && ruleKey !== RULE_FILTER_ALL_VALUE ? String(ruleKey) : null;
  sastFilterState.ruleKey = normalized && normalized.length ? normalized : null;
  if (syncDropdown) {
    syncRuleDropdownSelection(sastFilterState.ruleKey);
  }
  applySastFilters();
}

function setSastScopeFilter(scope) {
  const normalized = scope === "vuln" ? "vuln" : "all";
  sastFilterState.scope = normalized;
  $("#filter_all, #filter_vuln").removeClass("active");
  $("#filter_" + normalized).addClass("active");
  applySastFilters();
}

function populateSastRuleFilterOptions(items) {
  const map = new Map();
  const collection = Array.isArray(items)
    ? items
    : (items && typeof items === "object"
      ? Object.keys(items).map((key) => items[key])
      : []);
  if (collection.length) {
    collection.forEach((item) => {
      if (!item) return;
      const rawId = item?.metadata?.id || item?.module_metadata?.id || "";
      if (!rawId) return;
      const key = encodeURIComponent(rawId);
      const entry =
        map.get(key) ||
        {
          label: item?.metadata?.name || item?.module_metadata?.name || rawId,
          count: 0,
        };
      entry.count += 1;
      map.set(key, entry);
    });
  }
  controller._sastKnownRuleIds = new Set(map.keys());
  controller._sastRuleCounts = map;
  renderSastRuleFilterMenu(map);
}

function populateSastRuleFilterOptionsFromFindings(findings) {
  const map = new Map();
  if (Array.isArray(findings)) {
    findings.forEach((finding) => {
      if (!finding) return;
      const rawId = finding.ruleId || finding.id || "";
      if (!rawId) return;
      const key = encodeURIComponent(rawId);
      const entry =
        map.get(key) ||
        {
          label: finding.ruleName || finding.moduleName || rawId,
          count: 0,
        };
      entry.count += 1;
      map.set(key, entry);
    });
  }
  controller._sastKnownRuleIds = new Set(map.keys());
  controller._sastRuleCounts = map;
  renderSastRuleFilterMenu(map);
}

function renderSastRuleFilterMenu(map) {
  const $dropdown = getRuleFilterDropdown();
  if (!$dropdown.length) return;
  const menuItems = [
    `<div class="item" data-value="${RULE_FILTER_ALL_VALUE}">All rules</div>`,
  ];
  map.forEach((entry, key) => {
    const label = entry?.label || key;
    const count = typeof entry?.count === "number" ? entry.count : 0;
    menuItems.push(
      `<div class="item" data-value="${key}"><span class="description">${ptk_utils.escapeHtml(
        String(count)
      )}</span>${ptk_utils.escapeHtml(label)}</div>`
    );
  });
  $dropdown.find(".menu").html(menuItems.join(""));
  $dropdown.dropdown("refresh");
  if (sastFilterState.ruleKey && !map.has(sastFilterState.ruleKey)) {
    sastFilterState.ruleKey = null;
  }
  syncRuleDropdownSelection(sastFilterState.ruleKey);
  $dropdown.toggleClass("disabled", map.size === 0);
}

function applySastFilters() {
  const $attacks = $(".attack_info");
  if (!$attacks.length) {
    updateSastStatsFromCollection($attacks);
    return;
  }

  const fileCanon = sastFilterState.fileCanon;
  let $subset = $attacks;
  if (fileCanon) {
    $subset = $attacks.filter(function () {
      return sastAttackMatchesFile($(this), fileCanon);
    });
  }

  if (sastFilterState.ruleKey) {
    const ruleKey = sastFilterState.ruleKey;
    $subset = $subset.filter(function () {
      return ($(this).attr("data-rule-key") || "") === ruleKey;
    });
  }

  $attacks.hide();
  let $visible = $subset;
  if (sastFilterState.scope === "vuln") {
    $visible = $subset.not(".nonvuln");
  }
  $visible.show();
  updateSastStatsFromCollection($visible);
}

function initRuleFilterDropdown() {
  const $dropdown = getRuleFilterDropdown();
  if (!$dropdown.length) return;
  $dropdown.dropdown({
    onChange(value) {
      if (isRuleDropdownSyncing) return;
      setSastRuleFilter(value || RULE_FILTER_ALL_VALUE, false);
    },
  });
  syncRuleDropdownSelection(sastFilterState.ruleKey);
}

function getRuleFilterDropdown() {
  return $(RULE_FILTER_DROPDOWN_SELECTOR);
}

function syncRuleDropdownSelection(ruleKey) {
  const $dropdown = getRuleFilterDropdown();
  if (!$dropdown.length) return;
  const value = ruleKey || RULE_FILTER_ALL_VALUE;
  const current = $dropdown.dropdown("get value");
  if (current === value) return;
  isRuleDropdownSyncing = true;
  $dropdown.dropdown("set selected", value);
  isRuleDropdownSyncing = false;
}

function ensureSastRequestFilterIsValid() {
  if (!sastFilterState.fileCanon) return;
  const exists = $("#request_info .title.short_message_text").filter(function () {
    return ($(this).attr("data-file-canon") || "") === sastFilterState.fileCanon;
  }).length > 0;
  if (!exists) {
    sastFilterState.fileCanon = null;
  }
}

function ensureSastRuleFilterIsValid() {
  const $dropdown = getRuleFilterDropdown();
  if (!$dropdown.length) return;
  if (!sastFilterState.ruleKey) {
    syncRuleDropdownSelection(null);
    return;
  }
  const exists =
    $dropdown.find(`.item[data-value="${sastFilterState.ruleKey}"]`).length > 0;
  if (!exists) {
    sastFilterState.ruleKey = null;
    syncRuleDropdownSelection(null);
  }
}

function updateRequestFilterUI() {
  const current = sastFilterState.fileCanon;
  $("#request_info .title.short_message_text").each(function () {
    const matches = current && ($(this).attr("data-file-canon") || "") === current;
    $(this).toggleClass("active", !!matches);
    $(this).find(".filter.icon").toggleClass("primary", !!matches);
  });
}

function refreshSastFiltersAfterRender() {
  ensureSastRequestFilterIsValid();
  ensureSastRuleFilterIsValid();
  updateRequestFilterUI();
  applySastFilters();
}

function sastAttackMatchesFile($el, fileCanon) {
  if (!fileCanon) return true;
  const attrs = [
    "data-source-canon",
    "data-sink-canon",
    "data-source-base",
    "data-sink-base",
  ];
  for (const attr of attrs) {
    const value = $el.attr(attr);
    if (value && canonMatchesRequest(value, fileCanon)) {
      return true;
    }
  }
  return false;
}

function updateSastStatsFromCollection($collection) {
  const stats = collectSastStats($collection);
  rutils.bindStats(stats, "sast");
}

function collectSastStats($collection) {
  const stats = {
    findingsCount: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    rulesCount: 0,
  };
  if (!$collection || !$collection.length) {
    return stats;
  }

  const rules = new Set();
  stats.findingsCount = $collection.length;
  $collection.each(function () {
    const severity = ($(this).attr("data-severity") || "").toLowerCase();
    const ruleId = ($(this).attr("data-rule-id") || "").trim();
    if (severity === "critical") stats.critical++;
    else if (severity === "high") stats.high++;
    else if (severity === "medium") stats.medium++;
    else if (severity === "low") stats.low++;
    else if (severity === "info" || severity === "informational") stats.info++;
    if (ruleId) {
      rules.add(ruleId);
    }
  });
  stats.rulesCount = rules.size;
  return stats;
}

function canonMatchesRequest(value, fileCanon) {
  if (!value || !fileCanon) return false;
  const trimmed = String(value).trim();
  if (!trimmed) return false;
  if (trimmed === fileCanon) return true;
  if (trimmed.startsWith(fileCanon + " ::")) return true;
  const split = trimmed.split(/\s+::\s+/);
  if (split.length > 1 && split[0].trim() === fileCanon) return true;
  if (typeof rutils?.canonicalizeSastFileId === "function") {
    const aligned = rutils.canonicalizeSastFileId(trimmed);
    if (aligned && aligned === fileCanon) return true;
  }
  return false;
}

////////////////////////////////////
/* Chrome runtime events handlers */
////////////////////////////////////

browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (message.channel == "ptk_background2popup_sast") {
    const { type, payload, scanResult, info } = message;
    switch (type) {
      case "scan:start":
      case "file:start":
      case "file:end":
      case "module:start":
      case "module:end":
      case "scan:summary":
      case "scan:error":
        handleStructuredSastMessage(type, payload || message, scanResult);
        break;
    case "progress":
      bindAttackProgress({ info: info || payload });
      if (!controller._sastIsScanning) {
        controller._sastIsScanning = true;
        showRunningForm({ scanResult: controller.scanResult?.scanResult || { host: info?.host || "" } });
        hideScanForm();
        hideWelcomeForm();
      }
      break;
      case "findings_delta":
        applySastFindingsDelta(message);
        break;
      case "update findings":
        bindScanResult(message);
        break;
      default:
        break;
    }
  }
})
