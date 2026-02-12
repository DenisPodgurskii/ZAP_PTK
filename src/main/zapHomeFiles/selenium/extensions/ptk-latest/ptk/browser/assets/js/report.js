/* Author: Denis Podgurskii */
import { ptk_controller_index } from "../../../controller/index.js"
import { ptk_controller_sca } from "../../../controller/sca.js"
import { ptk_controller_rattacker } from "../../../controller/rattacker.js"
import { ptk_controller_iast } from "../../../controller/iast.js"
import { ptk_controller_sast } from "../../../controller/sast.js"
import { ptk_utils, ptk_jwtHelper } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import * as rutils from "../js/rutils.js"
import { normalizeScanResult } from "../js/scanResultViewModel.js"
import { default as dompurify } from "../../../packages/dompurify/purify.es.mjs"
import { redactText, redactHeaders, redactStorage, redactEvidence } from "./report/redaction.js"
import { buildCorrelationGroups } from "./report/correlation.js"
import { pdfTheme, setH1, setH2, setBody, setCode, setSmall } from "./report/pdfTheme.js"
import { createPdfLayout, clampCellText, formatUrlForTable } from "./report/pdfLayout.js"
import { buildEvidenceRows } from "./report/evidenceRenderer.js"
import { drawBadge, drawFlagIcon, drawReplayIcon, drawCheckIcon, drawRiskBarList, drawKeyValueBlock, normalizeEvidenceSummary, drawCodeBlock, drawHostBanner, drawSummaryCard, drawMutedText } from "./report/pdfComponents.js"

const jwtHelper = new ptk_jwtHelper()
const decoder = new ptk_decoder()

var tokens = new Array()
var tokenAdded = false
let index_controller = null
let reportLogoDataUrl = null
let severitySyncGuard = false

const SAST_ALLOWED_TAGS = ['p', 'ul', 'li', 'code', 'strong', 'em', 'a', 'br', 'pre'];
const SAST_ALLOWED_ATTRS = ['href', 'target', 'rel'];
const REPORT_SEVERITY_STYLES = {
    critical: { color: "red", icon: "fire", label: "Critical" },
    high: { color: "red", icon: "exclamation triangle", label: "High" },
    medium: { color: "orange", icon: "exclamation triangle", label: "Medium" },
    low: { color: "yellow", icon: "exclamation triangle", label: "Low" },
    info: { color: "blue", icon: "info circle", label: "Info" }
}
const EVIDENCE_SNIPPET_MAX = 800
const EXPORT_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
const UI_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
const STORAGE_TOKEN_KEY_REGEX = /(token|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|session)/i
const OWASP_VERSION = "2021"

const SEVERITY_FILTER_CONFIG = {
    dast: { container: "#rattacker_content", item: ".attack_info" },
    iast: { container: "#iast_report_items", item: ".iast_attack_card" },
    sast: { container: "#sast_report_items", item: ".sast-report-card" },
    sca: { container: "#sca_report_items", item: ".sca-report-card" }
}

const exportModel = {
    meta: {
        reportType: null,
        host: null,
        generatedAt: null,
        startTime: null,
        endTime: null,
        scanDuration: null,
        scanStatus: "Finished"
    },
    dashboard: {
        technologies: [],
        owaspHeaders: [],
        cves: [],
        headers: [],
        cookies: [],
        storage: [],
        storageDetails: {
            localStorage: [],
            sessionStorage: []
        },
        tokens: []
    },
    findings: [],
    sections: {
        dast: [],
        iast: [],
        sast: [],
        sca: []
    },
    summary: {
        byEngine: {},
        bySeverity: {}
    },
    scanStats: {
        urlsSpidered: 0,
        uniqueInjectionPoints: 0,
        totalHttpRequests: 0,
        avgResponseTime: null,
        httpRequestErrors: 0,
        testsPerformed: [],
        testsTotal: 0,
        testsCompleted: 0
    },
    spiderResults: [],
    expectedSections: [],
    sectionsReady: {},
    expectedDashboardParts: {
        technologies: true,
        owasp: true,
        cves: true,
        headers: true,
        cookies: true,
        storage: true
    },
    dashboardPartsReady: {}
}
let exportModelReady = false

function initExportModel(reportType) {
    const normalized = reportType || "full"
    exportModel.meta.reportType = normalized
    exportModel.meta.generatedAt = null
    exportModel.meta.startTime = null
    exportModel.meta.endTime = null
    exportModel.meta.scanDuration = null
    exportModel.meta.scanStatus = "Finished"
    exportModel.findings = []
    exportModel.sections = {
        dast: [],
        iast: [],
        sast: [],
        sca: []
    }
    exportModel.summary = { byEngine: {}, bySeverity: {} }
    exportModel.scanStats = {
        urlsSpidered: 0,
        uniqueInjectionPoints: 0,
        totalHttpRequests: 0,
        avgResponseTime: null,
        httpRequestErrors: 0,
        testsPerformed: [],
        testsTotal: 0,
        testsCompleted: 0
    }
    exportModel.spiderResults = []
    exportModel.dashboard = {
        technologies: [],
        owaspHeaders: [],
        cves: [],
        headers: [],
        cookies: [],
        storage: [],
        storageDetails: {
            localStorage: [],
            sessionStorage: []
        },
        tokens: []
    }
    const expected = normalized === "full"
        ? ["dashboard", "rattacker", "iast", "sast", "sca"]
        : [normalized]
    exportModel.expectedSections = expected
    exportModel.sectionsReady = {}
    expected.forEach(section => {
        exportModel.sectionsReady[section] = false
    })
    exportModel.dashboardPartsReady = {}
    Object.keys(exportModel.expectedDashboardParts).forEach(part => {
        exportModel.dashboardPartsReady[part] = false
    })
    exportModelReady = false
    updateExportButtons()
}

function setExportMeta({ host, reportType } = {}) {
    if (reportType) {
        exportModel.meta.reportType = reportType
    }
    if (host) {
        exportModel.meta.host = host
    }
}

function normalizeExportSeverity(severity) {
    const normalized = String(severity || "").toLowerCase()
    if (EXPORT_SEVERITY_ORDER.includes(normalized)) return normalized
    return "info"
}

function truncateSnippet(value, max = EVIDENCE_SNIPPET_MAX) {
    if (!value) return ""
    const text = String(value)
    if (!Number.isFinite(max) || max <= 0) return text
    if (text.length <= max) return text
    return `${text.slice(0, Math.max(0, max - 3))}...`
}

function truncateEvidenceBlock(value, { maxChars = 3000, maxLines = 30 } = {}) {
    if (!value) return { text: "", truncated: false }
    const text = String(value)
    const lines = text.split(/\r?\n/)
    let truncated = false
    let trimmed = text
    if (lines.length > maxLines) {
        trimmed = lines.slice(0, maxLines).join("\n")
        truncated = true
    }
    if (trimmed.length > maxChars) {
        trimmed = trimmed.slice(0, Math.max(0, maxChars - 24))
        truncated = true
    }
    if (truncated) {
        trimmed = `${trimmed}\n...[truncated]...`
    }
    return { text: trimmed, truncated }
}

function normalizeTraceForExport(trace) {
    if (!trace) return ""
    if (Array.isArray(trace)) return trace
    if (typeof trace === "object") {
        try {
            return JSON.stringify(trace, null, 2)
        } catch (_) {
            return String(trace)
        }
    }
    return String(trace)
}

function formatLocationRange(location) {
    if (!location || typeof location !== "object") return ""
    const start = location.start || location.sourceLoc?.start || location.sinkLoc?.start || null
    const end = location.end || location.sourceLoc?.end || location.sinkLoc?.end || null
    const startLine = start?.line ?? location.line ?? location.row ?? null
    const startCol = start?.column ?? location.column ?? null
    const endLine = end?.line ?? null
    const endCol = end?.column ?? null
    if (startLine == null && startCol == null) return ""
    const startText = `L${startLine ?? ""}${startCol != null ? `:${startCol}` : ""}`
    if (endLine == null && endCol == null) return startText
    const endText = `L${endLine ?? ""}${endCol != null ? `:${endCol}` : ""}`
    return `${startText}–${endText}`
}

function normalizeEndpointDetails(endpoint) {
    if (!endpoint) return null
    if (typeof endpoint === "string") return { name: endpoint }
    if (typeof endpoint !== "object") return null
    return {
        name: endpoint.name || endpoint.label || endpoint.sourceName || endpoint.sinkName || endpoint.id || "",
        file: endpoint.file || endpoint.sourceFile || endpoint.sinkFile || "",
        location: endpoint.loc || endpoint.sourceLoc || endpoint.sinkLoc || endpoint.location || null
    }
}

function normalizeIastFlowForExport(flow) {
    if (!flow) return ""
    if (Array.isArray(flow)) {
        return flow.map(entry => {
            if (entry === null || entry === undefined) return ""
            if (typeof entry === "string") return entry
            try {
                return JSON.stringify(entry, null, 2)
            } catch (_) {
                return String(entry)
            }
        }).filter(Boolean).join("\n")
    }
    if (typeof flow === "object") {
        try {
            return JSON.stringify(flow, null, 2)
        } catch (_) {
            return String(flow)
        }
    }
    return String(flow)
}

function resolveIastProof(evidence = {}, fallback = {}) {
    const direct = evidence?.matched || evidence?.proof || evidence?.message
    const contextValue = evidence?.context?.value ?? evidence?.context?.valuePreview ?? evidence?.context?.innerHTML ?? evidence?.context?.text
    const fallbackValue = fallback?.matched || fallback?.proof || fallback?.message
    const resolved = direct || contextValue || fallbackValue
    return resolved ? String(resolved) : ""
}

function formatConfidenceLabel(value) {
    if (!Number.isFinite(value)) return ""
    if (value >= 80) return "High"
    if (value >= 50) return "Medium"
    return "Low"
}

async function loadReportLogoDataUrl() {
    if (reportLogoDataUrl) return reportLogoDataUrl
    try {
        const response = await fetch("assets/images/icon.png")
        const blob = await response.blob()
        reportLogoDataUrl = await new Promise((resolve, reject) => {
            const reader = new FileReader()
            reader.onload = () => resolve(reader.result)
            reader.onerror = () => reject(reader.error)
            reader.readAsDataURL(blob)
        })
        return reportLogoDataUrl
    } catch (_) {
        return null
    }
}

function formatTimestamp(value) {
    if (!value) return ""
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) {
        return String(value)
    }
    const pad = (num) => String(num).padStart(2, "0")
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function formatLocationSummary(location = {}) {
    if (!location || typeof location !== "object") return ""
    const parts = []
    if (location.url) parts.push(String(location.url))
    if (location.file) parts.push(String(location.file))
    const line = location.line != null ? `L${location.line}` : ""
    const column = location.column != null ? `C${location.column}` : ""
    if (line || column) {
        parts.push([line, column].filter(Boolean).join(":"))
    }
    if (location.method) parts.push(String(location.method))
    if (location.param) parts.push(`param:${location.param}`)
    return parts.filter(Boolean).join(" ")
}

function formatFindingId(prefix, index) {
    const num = String(index + 1).padStart(4, "0")
    return `${prefix}-${num}`
}

function buildSummaryTableRows(model) {
    const summaryByEngine = model.summary?.byEngine || {}
    const summaryBySeverity = model.summary?.bySeverity || {}
    const engineSeverityCounts = model.findings.reduce((acc, finding) => {
        const engine = finding.engine || "UNKNOWN"
        const severity = normalizeSeverityKey(finding.severity)
        if (!acc[engine]) {
            acc[engine] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        }
        acc[engine][severity] += 1
        return acc
    }, {})
    const engines = Object.keys(summaryByEngine).length
        ? Object.keys(summaryByEngine)
        : Object.keys(engineSeverityCounts)
    const rows = engines.map(engine => {
        const sev = engineSeverityCounts[engine] || { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        const total = summaryByEngine[engine] ?? Object.values(sev).reduce((sum, val) => sum + val, 0)
        const engineKey = String(engine || "").toLowerCase()
        const hasFilter = !!SEVERITY_FILTER_CONFIG[engineKey]
        const selected = hasFilter ? new Set(getSelectedSeverities(engineKey)) : new Set()
        const renderSeverityCell = (severity) => {
            const count = sev[severity] || 0
            if (!hasFilter) return escapeText(String(count), "")
            const checked = selected.has(severity)
            return `<div class="summary-sev-cell">` +
                `<span class="summary-sev-count">${escapeText(String(count), "")}</span>` +
                `<div class="ui mini checkbox ptk-summary-checkbox">` +
                `<input type="checkbox" class="severity-filter summary-severity-filter" data-engine="${engineKey}" data-severity="${severity}"${checked ? " checked" : ""}>` +
                `<label></label>` +
                `</div>` +
                `</div>`
        }
        return {
            isTotal: false,
            cells: [
                escapeText(String(engine || "UNKNOWN"), ""),
                renderSeverityCell("critical"),
                renderSeverityCell("high"),
                renderSeverityCell("medium"),
                renderSeverityCell("low"),
                renderSeverityCell("info"),
                escapeText(String(total), "")
            ]
        }
    })
    const totals = {
        critical: summaryBySeverity.critical || 0,
        high: summaryBySeverity.high || 0,
        medium: summaryBySeverity.medium || 0,
        low: summaryBySeverity.low || 0,
        info: summaryBySeverity.info || 0
    }
    const totalAll = Object.values(totals).reduce((sum, val) => sum + val, 0)
    rows.push({
        isTotal: true,
        cells: [
            "Total",
            escapeText(String(totals.critical), ""),
            escapeText(String(totals.high), ""),
            escapeText(String(totals.medium), ""),
            escapeText(String(totals.low), ""),
            escapeText(String(totals.info), ""),
            escapeText(String(totalAll), "")
        ]
    })
    return rows
}

function resolveOverallRisk(counts = {}) {
    if (counts.critical > 0) return "critical"
    if (counts.high > 0) return "high"
    if (counts.medium > 0) return "medium"
    if (counts.low > 0) return "low"
    return "info"
}

function normalizeOwaspEntries(value) {
    const raw = Array.isArray(value) ? value : (value ? [value] : [])
    return raw.map(entry => {
        if (!entry) return null
        if (typeof entry === "string") {
            const cleaned = entry.replace(/\s+/g, " ").trim()
            const normalized = cleaned.replace(/^(A\d{2}:\d{4})\s*-\s*/i, "$1 - ").replace(/^(A\d{2}:\d{4})(?=[A-Za-z])/i, "$1 - ")
            return normalized
        }
        if (typeof entry === "object") {
            const id = entry.id || entry.code || entry.key || ""
            const name = entry.name || entry.title || ""
            const year = entry.year || entry.version || ""
            if (id && year && name) return `${id}:${year} - ${name}`
            if (id && name) return `${id} - ${name}`
            if (name) return name
        }
        return String(entry)
    }).filter(Boolean)
}

function resolveOwaspList(finding) {
    const sources = [
        finding?.owasp,
        finding?.metadata?.owasp,
        finding?.module_metadata?.owasp,
        finding?.owaspLegacy
    ]
    const merged = sources.flatMap(entry => {
        if (!entry) return []
        return Array.isArray(entry) ? entry : [entry]
    })
    const normalized = normalizeOwaspEntries(merged)
    return Array.from(new Set(normalized))
}

function normalizeCweEntries(value) {
    if (!value) return []
    if (Array.isArray(value)) return value.map(String)
    if (typeof value === "string") {
        return value.split(",").map(item => item.trim()).filter(Boolean)
    }
    return [String(value)]
}

function getByPath(obj, path) {
    if (!obj || !path) return undefined
    return path.split(".").reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : undefined), obj)
}

function firstDefined(sources, paths) {
    for (const source of sources) {
        for (const path of paths) {
            const value = getByPath(source, path)
            if (value !== undefined && value !== null && value !== "") return value
        }
    }
    return undefined
}

function inferEnvironmentFromHost(host) {
    if (!host) return "N/A"
    const value = String(host).toLowerCase()
    if (value.includes("localhost") || value.includes("127.0.0.1")) return "Local"
    if (value.includes("staging") || value.includes("stage")) return "Staging"
    if (value.includes("dev")) return "Dev"
    return "Production"
}

function formatDateValue(value) {
    if (!value) return "N/A"
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return String(value)
    return date.toISOString().replace("T", " ").slice(0, 16)
}

function formatDuration(start, end) {
    if (!start || !end) return "N/A"
    const startDate = new Date(start)
    const endDate = new Date(end)
    if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) return "N/A"
    const ms = Math.max(0, endDate.getTime() - startDate.getTime())
    const mins = Math.floor(ms / 60000)
    const hours = Math.floor(mins / 60)
    const remMins = mins % 60
    if (hours > 0) return `${hours}h ${remMins}m`
    return `${remMins}m`
}

function resolveReportContext(sourceModel = {}) {
    const sources = [
        sourceModel.meta || {},
        sourceModel || {},
        exportModel.meta || {},
        exportModel || {},
        index_controller?.tab || {},
        index_controller?.tab?.scanResult || {},
        index_controller?.tab?.scanContext || {},
        index_controller?.tab?.scan || {}
    ]

    const target = firstDefined(sources, ["target.origin", "target.url", "meta.target", "scan.target", "host", "origin"]) || sourceModel.meta?.host || "N/A"
    const startTime = firstDefined(sources, ["meta.startedAt", "scan.startedAt", "startedAt", "timestamps.start", "startTime"])
    const endTime = firstDefined(sources, ["meta.finishedAt", "scan.endedAt", "endedAt", "timestamps.end", "endTime"])
    const ptkVersion = firstDefined(sources, ["meta.ptkVersion", "ptk.version", "client.version", "version"]) || "N/A"
    const policyName = firstDefined(sources, ["policy.name", "scan.policyName", "meta.policy", "profile.name"]) || "N/A"
    const scopeSummary = firstDefined(sources, ["scope", "meta.scope", "scan.scope"]) || "N/A"
    const authUsed = firstDefined(sources, ["auth.used", "meta.authUsed", "scan.authenticated"])

    const authResolved = authUsed === true
        ? "Yes"
        : authUsed === false
            ? "No"
            : "Unknown"

    return {
        target: target || "N/A",
        environment: firstDefined(sources, ["environment", "meta.environment", "scan.environment"]) || inferEnvironmentFromHost(target),
        scanStart: startTime ? formatDateValue(startTime) : "N/A",
        scanEnd: endTime ? formatDateValue(endTime) : "N/A",
        duration: formatDuration(startTime, endTime),
        ptkVersion,
        policyName,
        scopeSummary: typeof scopeSummary === "string" ? scopeSummary : JSON.stringify(scopeSummary),
        authUsed: authResolved
    }
}

function inferOwnerHint(finding) {
    const engine = String(finding?.engine || "").toUpperCase()
    const title = String(finding?.title || "").toLowerCase()
    const asset = String(finding?.location?.url || finding?.location?.route || finding?.location?.file || "").toLowerCase()
    if (engine === "SCA") return "Dependency"
    if (engine === "SAST") {
        if (title.includes("dom") || title.includes("xss") || asset.endsWith(".js") || asset.endsWith(".ts") || asset.endsWith(".jsx") || asset.endsWith(".tsx")) {
            return "Frontend"
        }
        return "App"
    }
    if (engine === "DAST" || engine === "IAST") {
        if (asset.includes("/api")) return "API"
        return "App"
    }
    return "App"
}

function inferWhyItMatters(finding) {
    const title = String(finding?.title || "").toLowerCase()
    if (title.includes("xss")) return "May allow script execution and session compromise."
    if (title.includes("sql")) return "May allow data exfiltration or data manipulation."
    if (title.includes("ssrf")) return "May enable access to internal services."
    if (title.includes("csrf")) return "May allow unauthorized actions via forged requests."
    if (title.includes("rce") || title.includes("remote code")) return "May allow remote code execution."
    if (title.includes("xxe")) return "May allow file disclosure or SSRF via XML parsers."
    if (title.includes("jwt") || title.includes("token")) return "May allow token abuse or session hijacking."
    if (title.includes("cors")) return "May allow unauthorized cross-origin access."
    if (title.includes("header")) return "Weak headers reduce browser protection."
    if (finding?.engine === "SCA") return "Known vulnerable dependency increases risk."
    return "May impact security posture and require remediation."
}

function inferFix(finding) {
    const title = String(finding?.title || "").toLowerCase()
    if (finding?.engine === "SCA") return "Upgrade to a secure version."
    if (title.includes("xss")) return "Encode output and use safe DOM APIs."
    if (title.includes("sql")) return "Use parameterized queries/ORM."
    if (title.includes("ssrf")) return "Validate URLs and block internal ranges."
    if (title.includes("csrf")) return "Add CSRF tokens and SameSite cookies."
    if (title.includes("rce") || title.includes("remote code")) return "Avoid dynamic code execution; validate inputs."
    if (title.includes("xxe")) return "Disable external entities."
    if (title.includes("jwt") || title.includes("token")) return "Store tokens securely; validate signing."
    if (title.includes("cors")) return "Restrict allowed origins and methods."
    if (title.includes("header")) return "Set recommended security headers."
    return "Apply recommended validation and security controls."
}

function buildExecutiveConclusion(model, tiers) {
    const severity = model.summary?.bySeverity || {}
    if (tiers.confirmedHigh > 0 || severity.critical > 0 || severity.high > 0) {
        return "Confirmed high-risk issues detected; prioritize remediation."
    }
    if (tiers.likely > 0) {
        return "Likely issues detected; validate and prioritize remediation."
    }
    let line = "No confirmed high-risk issues; review potential findings and hardening opportunities."
    const sastCount = model.sections?.sast?.length || 0
    const total = model.findings.length || 1
    if (sastCount / total > 0.6) {
        line += " SAST findings skew low/medium and may include false positives."
    }
    return line
}

function buildTopRisksLabel(summary = {}) {
    return "Top 5 Highest Risks"
}

function buildMappingSummary(finding) {
    const cwe = Array.isArray(finding?.cwe) ? finding.cwe : (finding?.cwe ? [finding.cwe] : [])
    const owasp = resolveOwaspList(finding)
    const cweText = cwe.length ? `CWE: ${cwe.join(", ")}` : ""
    const owaspText = owasp.length
        ? `OWASP: ${owasp.join(", ")}`
        : ""
    return [cweText, owaspText].filter(Boolean).join(" | ") || "N/A"
}

function buildReferenceSummary(finding) {
    const refs = finding?.references || []
    if (!refs.length) return "N/A"
    return refs
        .map(ref => ref?.url || ref)
        .filter(Boolean)
        .slice(0, 2)
        .join(", ")
}

function buildReferenceLinksHtml(finding) {
    const refs = finding?.references || []
    if (!refs.length) return "N/A"
    return refs
        .map(ref => ref?.url || ref)
        .filter(Boolean)
        .slice(0, 2)
        .map(url => {
            const safeUrl = escapeText(url, "")
            return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${safeUrl}</a>`
        })
        .join(", ")
}

function renderMappingSectionMarkdown(cweList, owaspList) {
    const cwe = normalizeCweEntries(cweList)
    const owasp = Array.from(new Set(normalizeOwaspEntries(owaspList)))
    const lines = []
    if (cwe.length) lines.push(`**CWE:** ${escapeMarkdownText(cwe.join(", "))}`)
    if (owasp.length) lines.push(`**OWASP:** ${escapeMarkdownText(owasp.join(", "))}`)
    return lines.join("\n")
}

function stripHtmlToText(value) {
    if (!value) return ""
    const safeHtml = sanitizeRichText(String(value))
    const div = document.createElement("div")
    div.innerHTML = safeHtml
    return (div.textContent || div.innerText || "").trim()
}

function groupFindingsForExec(findings = [], { keyFn, maxItems = 10 } = {}) {
    const map = new Map()
    findings.forEach(item => {
        const key = keyFn ? keyFn(item) : (item.title || item.findingId || "finding")
        if (!map.has(key)) {
            map.set(key, { item, count: 0 })
        }
        const entry = map.get(key)
        entry.count += 1
        if (severityRank(item?.severity) < severityRank(entry.item?.severity)) {
            entry.item = item
        }
        const conf = Number.isFinite(item?.confidence) ? item.confidence : null
        const entryConf = Number.isFinite(entry.item?.confidence) ? entry.item.confidence : null
        if (conf !== null && (entryConf === null || conf > entryConf)) {
            entry.item = item
        }
    })
    return Array.from(map.values())
        .sort((a, b) => severityRank(a.item?.severity) - severityRank(b.item?.severity))
        .slice(0, maxItems)
}

function normalizeScaKey(item) {
    const name = item?.componentName || ""
    const version = item?.componentVersion || ""
    if (name || version) {
        return `${name}@${version || "unknown"}`
    }
    const title = String(item?.title || "")
    const base = title.split(" - ")[0].trim()
    return base || title || "component"
}

function buildCorrelationReason(group) {
    const engines = group.engines || []
    const hasDastOrIast = engines.includes("DAST") || engines.includes("IAST")
    const hasSast = engines.includes("SAST")
    if (hasDastOrIast && hasSast) return "Confirmed by runtime + code evidence."
    if (hasDastOrIast) return "Confirmed by runtime evidence across engines."
    return "Multiple engine signals increase confidence."
}

function renderSummaryBlocks(doc, layout, model, cursorY) {
    const margin = layout.margin
    const contentWidth = layout.pageWidth - margin * 2
    const blockGap = pdfTheme.spacing.sm
    const blockWidth = (contentWidth - blockGap * 2) / 3
    const blockHeight = 110
    const counts = model.summary?.bySeverity || {}
    const overall = resolveOverallRisk(counts)
    const overallLabel = overall.toUpperCase()
    const overallColor = pdfTheme.severityColors[overall] || pdfTheme.severityColors.info

    // Block 1: Overall Risk Level
    drawSummaryCard(doc, { x: margin, y: cursorY, width: blockWidth, height: blockHeight })
    setBody(doc, pdfTheme)
    doc.setFont("helvetica", "bold")
    doc.text("Overall risk level:", margin + 10, cursorY + 18)
    drawBadge(doc, overallLabel, { x: margin + 10, y: cursorY + 28, fill: overallColor })

    // Block 2: Risk Ratings
    drawSummaryCard(doc, { x: margin + blockWidth + blockGap, y: cursorY, width: blockWidth, height: blockHeight })
    const riskY = cursorY + 18
    const riskX = margin + blockWidth + blockGap + 10
    drawRiskBarList(doc, {
        x: riskX,
        y: riskY,
        counts,
        labelWidth: 50,
        barMaxWidth: Math.max(40, blockWidth - 70)
    })

    // Block 3: Scan Information (matching reference PDF)
    drawSummaryCard(doc, { x: margin + (blockWidth + blockGap) * 2, y: cursorY, width: blockWidth, height: blockHeight })
    const infoX = margin + (blockWidth + blockGap) * 2 + 10
    const infoY = cursorY + 18
    const testsCount = model.scanStats?.testsTotal || model.scanStats?.testsPerformed?.length || 0
    const scanStatus = model.meta.scanStatus || "Finished"
    drawKeyValueBlock(doc, {
        x: infoX,
        y: infoY,
        labelWidth: 75,
        rows: [
            ["Start time:", model.meta.startTime || model.meta.generatedAt || ""],
            ["Finish time:", model.meta.endTime || ""],
            ["Scan duration:", model.meta.scanDuration || ""],
            ["Tests performed:", String(testsCount)]
        ]
    })
    // Draw scan status badge at bottom of info block
    const statusColor = scanStatus === "Finished" ? [76, 175, 80] : [255, 152, 0]
    drawBadge(doc, scanStatus, { x: infoX, y: cursorY + blockHeight - 24, fill: statusColor })

    return cursorY + blockHeight + pdfTheme.spacing.md
}

function resolveFindingCategory(finding) {
    const parts = []
    const cwe = Array.isArray(finding?.cwe) ? finding.cwe : (finding?.cwe ? [finding.cwe] : [])
    if (cwe.length) parts.push(cwe.join(", "))
    const owasp = Array.isArray(finding?.owasp) ? finding.owasp : (finding?.owasp ? [finding.owasp] : [])
    if (owasp.length) {
        const label = owasp
            .map(entry => (typeof entry === "string" ? entry : entry?.id || entry?.name || ""))
            .filter(Boolean)
            .join(", ")
        if (label) parts.push(label)
    }
    return parts.join(" | ")
}

function formatAssetForOverview(location = {}) {
    const raw = location.url || location.route || location.file || ""
    const formatted = formatUrlForTable(raw, "overview")
    return clampCellText(formatted, { maxChars: 90, maxLines: 2 })
}

function formatAssetForDetail(location = {}) {
    const raw = location.url || location.route || location.file || ""
    const base = formatUrlForTable(raw, "overview")
    const line = location.line != null ? `L${location.line}` : ""
    const column = location.column != null ? `C${location.column}` : ""
    const suffix = line || column ? ` ${[line, column].filter(Boolean).join(":")}` : ""
    return `${base}${suffix}`.trim()
}

function buildOverviewColumnStyles() {
    return {
        0: { cellWidth: 60 },
        1: { cellWidth: 150 },
        2: { cellWidth: 60 },
        3: { cellWidth: 70 },
        4: { cellWidth: 80 },
        5: { cellWidth: 95 }
    }
}

function isJwtToken(value) {
    if (!value) return false
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(String(value))
}

function decodeJwtPayload(token) {
    if (!isJwtToken(token)) return null
    try {
        const payload = token.split(".")[1]
        const base64 = payload.replace(/-/g, "+").replace(/_/g, "/")
        const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=")
        const json = atob(padded)
        return JSON.parse(json)
    } catch (_) {
        return null
    }
}

function buildTokenSummaryEntries(dashboard = {}) {
    const entries = []
    const addEntry = (source, key, value) => {
        if (!value) return
        const token = String(value)
        const isJwt = isJwtToken(token)
        const payload = isJwt ? decodeJwtPayload(token) : null
        let validity = "present"
        if (isJwt) {
            if (!payload) {
                validity = "malformed"
            } else if (payload.exp) {
                const exp = Number(payload.exp)
                if (Number.isFinite(exp)) {
                    validity = exp * 1000 < Date.now() ? "expired" : "exp present"
                }
            } else {
                validity = "exp missing"
            }
        }
        entries.push({
            source,
            key,
            tokenType: isJwt ? "JWT" : "opaque",
            validity,
            note: source.includes("localStorage")
                ? "token stored in localStorage is high risk for XSS"
                : ""
        })
    }

    const storageDetails = dashboard.storageDetails || {}
    const addFromStorage = (source, list = []) => {
        list.forEach(entry => {
            if (!entry || !entry.key) return
            if (STORAGE_TOKEN_KEY_REGEX.test(String(entry.key))) {
                addEntry(source, entry.key, entry.value)
            }
        })
    }
    addFromStorage("localStorage", storageDetails.localStorage || [])
    addFromStorage("sessionStorage", storageDetails.sessionStorage || [])

    const cookies = dashboard.cookies || []
    cookies.forEach(cookie => {
        if (STORAGE_TOKEN_KEY_REGEX.test(cookie?.name || "")) {
            addEntry("cookie", cookie.name, cookie.value)
        }
    })

    const headers = dashboard.headers || []
    headers.forEach(header => {
        if (STORAGE_TOKEN_KEY_REGEX.test(header?.name || "")) {
            addEntry("header", header.name, header.value)
        }
    })

    return entries
}

function buildTokenPayloadForTechnical(tokenValue, opts = {}) {
    if (!tokenValue) return ""
    const payload = decodeJwtPayload(tokenValue)
    if (!payload || typeof payload !== "object") return ""
    const allowlist = new Set(["iss", "aud", "sub", "iat", "nbf", "exp", "jti", "scope", "roles", "role", "azp", "kid", "typ"])
    const blocked = /(email|password|secret|hash|totp|phone|address|name|username)/i
    const result = {}
    Object.keys(payload).forEach(key => {
        if (!allowlist.has(key)) return
        if (blocked.test(key)) return
        const value = payload[key]
        if (value === undefined || value === null) return
        const str = typeof value === "string" ? value : JSON.stringify(value)
        result[key] = str.length > 80 ? `${str.slice(0, 77)}...` : str
    })
    return Object.keys(result).length ? JSON.stringify(result, null, 2) : ""
}

function buildReferenceList(links) {
    if (!links) return []
    if (Array.isArray(links)) {
        return links.map(entry => {
            if (!entry) return null
            if (typeof entry === "string") return { title: null, url: entry }
            if (typeof entry === "object") return { title: entry.title || entry.name || null, url: entry.url || entry.href || null }
            return null
        }).filter(entry => entry?.url)
    }
    if (typeof links === "object") {
        return Object.entries(links)
            .map(([title, url]) => ({ title, url }))
            .filter(entry => entry.url)
    }
    return []
}

function updateExportButtons() {
    const ready = exportModelReady
    const enabled = ready && hasExportData()
    $('#export_pdf_btn').toggleClass('disabled', !enabled)
    $('#export_md_btn').toggleClass('disabled', !enabled)
    const $preset = $('#report_preset')
    $preset.prop('disabled', !ready).toggleClass('disabled', !ready)
    $preset.closest('.ui.dropdown').toggleClass('disabled', !ready)
    $('#pdf_include_sensitive').prop('disabled', !ready)
    if ($.fn.checkbox) {
        const $checkbox = $('#pdf_include_sensitive').closest('.ui.checkbox')
        if (ready) {
            $checkbox.checkbox("enable")
        } else {
            $checkbox.checkbox("disable")
        }
    }
    $('#export_loader').toggleClass('active', !ready).toggle(!ready)
}

function getSelectedSeverities(engine) {
    return $(`.severity-filter[data-engine="${engine}"]:checked:not(.summary-severity-filter)`)
        .map(function () {
            return normalizeSeverityKey($(this).data("severity"))
        })
        .get()
}

function applySeverityFilter(engine) {
    const config = SEVERITY_FILTER_CONFIG[engine]
    if (!config) return
    const selected = new Set(getSelectedSeverities(engine))
    const $items = $(`${config.container} ${config.item}`)
    if (!selected.size) {
        $items.hide()
        return
    }
    $items.each(function () {
        const severity = normalizeSeverityKey($(this).data("severity"))
        $(this).toggle(selected.has(severity))
    })
}

function applyAllSeverityFilters() {
    Object.keys(SEVERITY_FILTER_CONFIG).forEach(engine => applySeverityFilter(engine))
}

function syncSeverityCheckboxes(engine, severity, checked) {
    if (!engine || !severity) return
    const selector = `.severity-filter[data-engine="${engine}"][data-severity="${severity}"]`
    severitySyncGuard = true
    $(selector).each(function () {
        const $input = $(this)
        if ($input.prop("checked") === checked) return
        if ($.fn.checkbox) {
            const $wrapper = $input.closest('.ui.checkbox')
            if ($wrapper.length) {
                $wrapper.checkbox(checked ? "check" : "uncheck")
                return
            }
        }
        $input.prop("checked", checked)
    })
    severitySyncGuard = false
}

function getFilteredExportModel() {
    const filtered = {
        ...exportModel,
        findings: [],
        sections: {
            dast: [],
            iast: [],
            sast: [],
            sca: []
        },
        summary: {
            byEngine: {},
            bySeverity: {}
        }
    }
    const sectionIds = Object.keys(filtered.sections)
    sectionIds.forEach(sectionId => {
        const selected = new Set(getSelectedSeverities(sectionId))
        const source = exportModel.sections?.[sectionId] || []
        const next = selected.size
            ? source.filter(item => selected.has(normalizeSeverityKey(item?.severity)))
            : []
        filtered.sections[sectionId] = next
        filtered.findings = filtered.findings.concat(next)
    })
    const byEngine = {}
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    filtered.findings.forEach(finding => {
        const engine = finding.engine || "UNKNOWN"
        byEngine[engine] = (byEngine[engine] || 0) + 1
        const severity = normalizeSeverityKey(finding.severity)
        bySeverity[severity] = (bySeverity[severity] || 0) + 1
    })
    filtered.summary = { byEngine, bySeverity }
    return filtered
}

function buildReportModel(sourceModel, options = {}) {
    const preset = options.preset || "executive"
    const includeSensitiveEvidence = !!options.includeSensitiveEvidence
    const opts = { includeSensitiveEvidence }
    const rawGeneratedAt = sourceModel.meta?.generatedAt || exportModel.meta.generatedAt || new Date().toISOString()
    const model = {
        meta: {
            host: sourceModel.meta?.host || exportModel.meta.host || "unknown",
            reportType: sourceModel.meta?.reportType || exportModel.meta.reportType || "report",
            generatedAt: formatTimestamp(rawGeneratedAt),
            generatedAtRaw: rawGeneratedAt,
            logoDataUrl: options.logoDataUrl || null,
            preset,
            redactionApplied: true,
            context: resolveReportContext(sourceModel)
        },
        summary: { byEngine: {}, bySeverity: {} },
        dashboard: {
            technologies: sourceModel.dashboard?.technologies || [],
            owaspHeaders: sourceModel.dashboard?.owaspHeaders || [],
            cves: sourceModel.dashboard?.cves || [],
            headers: sourceModel.dashboard?.headers || [],
            cookies: sourceModel.dashboard?.cookies || [],
            storage: sourceModel.dashboard?.storage || [],
            storageDetails: sourceModel.dashboard?.storageDetails || { localStorage: [], sessionStorage: [] },
            tokens: sourceModel.dashboard?.tokens || [],
            tokenSummary: [],
            tokenPayloadNote: ""
        },
        sections: { dast: [], iast: [], sast: [], sca: [] },
        findings: [],
        correlation: [],
        scanStats: sourceModel.scanStats || {
            urlsSpidered: 0,
            uniqueInjectionPoints: 0,
            totalHttpRequests: 0,
            avgResponseTime: null,
            httpRequestErrors: 0,
            testsPerformed: [],
            testsTotal: 0,
            testsCompleted: 0
        },
        spiderResults: sourceModel.spiderResults || []
    }

    model.dashboard.headers = redactHeaders(model.dashboard.headers, opts)
    model.dashboard.cookies = model.dashboard.cookies.map(item => ({
        ...item,
        value: redactText(item.value, opts)
    }))
    const redactStorageEntries = (entries = []) => {
        return entries.map(entry => {
            const key = entry?.key || ""
            if (STORAGE_TOKEN_KEY_REGEX.test(String(key)) && !includeSensitiveEvidence) {
                return { ...entry, value: "[REDACTED]" }
            }
            return { ...entry, value: redactText(entry?.value, opts) }
        })
    }
    model.dashboard.storageDetails = {
        localStorage: redactStorageEntries(model.dashboard.storageDetails.localStorage || []),
        sessionStorage: redactStorageEntries(model.dashboard.storageDetails.sessionStorage || [])
    }
    const rawTokens = model.dashboard.tokens || []
    model.dashboard.tokens = redactStorage(rawTokens, opts)
    model.dashboard.tokenSummary = buildTokenSummaryEntries(sourceModel.dashboard || {})
    if (preset === "executive") {
        model.dashboard.tokens = []
        model.dashboard.tokenPayloadNote = "Token payloads omitted in Executive exports."
    } else {
        model.dashboard.tokens = rawTokens.map(entry => {
            const tokenValue = entry?.token || ""
            const payload = buildTokenPayloadForTechnical(tokenValue, opts)
            const redactedToken = redactText(tokenValue, opts)
            return {
                ...entry,
                token: redactedToken,
                payload
            }
        }).filter(entry => entry.payload)
        model.dashboard.tokenPayloadNote = "Payload fields are allowlisted; sensitive fields are omitted."
    }

    const sectionMap = [
        { id: "dast", prefix: "DAST" },
        { id: "iast", prefix: "IAST" },
        { id: "sast", prefix: "SAST" },
        { id: "sca", prefix: "SCA" }
    ]

    const byEngine = {}
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }

    sectionMap.forEach(section => {
        const raw = sourceModel.sections?.[section.id] || []
        const sorted = raw.slice().sort((a, b) => severityRank(a?.severity) - severityRank(b?.severity))
        const mapped = sorted.map((finding, index) => {
            const confidence = Number.isFinite(finding?.confidence) ? finding.confidence : null
            const evidence = redactEvidence(finding?.evidence || {}, opts)
            const request = truncateEvidenceBlock(evidence?.requestSnippet || "")
            const response = truncateEvidenceBlock(evidence?.responseSnippet || "")
            const code = truncateEvidenceBlock(evidence?.codeSnippet || "")
            const notes = truncateEvidenceBlock(evidence?.notes || "")
            const evidenceTruncated = request.truncated || response.truncated || code.truncated || notes.truncated
            return {
                ...finding,
                findingId: formatFindingId(section.prefix, index),
                engine: section.prefix,
                category: resolveFindingCategory(finding),
                confidence,
                confidenceLabel: formatConfidenceLabel(confidence),
                evidence: {
                    ...evidence,
                    requestSnippet: redactText(request.text, opts),
                    responseSnippet: redactText(response.text, opts),
                    codeSnippet: redactText(code.text, opts),
                    notes: redactText(notes.text, opts),
                    evidenceTruncated
                }
            }
        })
        model.sections[section.id] = mapped
        model.findings = model.findings.concat(mapped)
        if (mapped.length) byEngine[section.prefix] = mapped.length
    })

    model.findings.forEach(finding => {
        const severity = normalizeSeverityKey(finding.severity)
        bySeverity[severity] = (bySeverity[severity] || 0) + 1
    })
    model.summary = { byEngine, bySeverity }
    model.correlation = buildCorrelationGroups(model.findings)
    return model
}

function hasExportData() {
    if (exportModel.findings.length) return true
    const dashboard = exportModel.dashboard || {}
    return Object.values(dashboard).some(list => Array.isArray(list) && list.length)
}

function markSectionReady(section) {
    if (!section) return
    exportModel.sectionsReady[section] = true
    updateExportReady()
}

function markDashboardPartReady(part) {
    if (!part) return
    exportModel.dashboardPartsReady[part] = true
    updateExportDashboardModel()
    const allPartsReady = Object.keys(exportModel.expectedDashboardParts)
        .every(key => exportModel.dashboardPartsReady[key])
    if (allPartsReady) {
        markSectionReady("dashboard")
    }
}

function updateExportReady() {
    exportModelReady = exportModel.expectedSections
        .every(section => exportModel.sectionsReady[section])
    updateExportButtons()
}

function updateSummarySegment() {
    const $segment = $('#summary_segment')
    if (!$segment.length) return
    const $content = $('#summary_segment_content')
    if (!exportModelReady && !hasExportData()) {
        $segment.show()
        $content.hide()
        $('#summary_executive_extras').hide()
        return
    }
    const model = getFilteredExportModel()
    $segment.show()
    $content.show()
    $('#summary_executive_extras').show()

    const counts = model.summary?.bySeverity || {}
    const max = Math.max(...Object.values(counts), 1)
    $('#summary_risk_chart .risk-bar-item').each(function () {
        const severity = normalizeSeverityKey($(this).data("severity"))
        const count = counts[severity] || 0
        const widthPct = count ? Math.max(6, (count / max) * 100) : 0
        $(this).find('.risk-count').text(String(count))
        $(this).find('.risk-bar').css('width', `${widthPct}%`)
    })

    const rows = buildSummaryTableRows(model)
    const $tbody = $('#summary_findings_tbody')
    $tbody.empty()
    rows.forEach(row => {
        const cells = row.cells.map(cell => `<td>${cell}</td>`).join("")
        $tbody.append(`<tr${row.isTotal ? ' class="summary-total-row"' : ''}>${cells}</tr>`)
    })
    if ($.fn.checkbox) {
        $tbody.find('.ptk-summary-checkbox').checkbox()
    }

    renderSummaryRemediation(counts)
}

function renderSummaryRemediation(severityCounts = {}) {
    $('#summary_remediation_content').html(`
        <table class="ui celled compact table">
            <tbody>
                <tr><td><strong>Fix now (0–7 days)</strong></td><td>${(severityCounts.critical || 0) + (severityCounts.high || 0)}</td></tr>
                <tr><td><strong>Fix soon (7–30 days)</strong></td><td>${severityCounts.medium || 0}</td></tr>
                <tr><td><strong>Backlog</strong></td><td>${(severityCounts.low || 0) + (severityCounts.info || 0)}</td></tr>
            </tbody>
        </table>
    `)
}

function updateMethodologyFooter(reportModel, { preset } = {}) {
    const $footer = $('#report_methodology_footer')
    if (!$footer.length) return
    if (!exportModelReady && !hasExportData()) {
        $footer.hide().text("")
        return
    }
    const mode = preset || $('#report_preset').val() || "technical"
    const model = reportModel || buildReportModel(getFilteredExportModel(), { preset: mode })
    const context = model.meta?.context || {}
    const methodologyText = mode === "executive"
        ? "Report generated using OWASP PTK scanning engines. Executive preset includes top findings only and excludes sensitive evidence by default. Results depend on scan coverage and target responsiveness."
        : "Report generated using OWASP PTK scanning engines. Results depend on scan coverage and target responsiveness."
    const scopeValue = context.scopeSummary && context.scopeSummary !== "N/A"
        ? context.scopeSummary
        : "N/A"
    const limitationsText = "Results depend on available routes and auth context; some flows may not be covered."
    $footer.html(`
        <div style="margin-top: 8px;"></div>
        <div>${escapeText(methodologyText, "")}</div>
        <div><strong>Scope:</strong> ${escapeText(scopeValue, "")}</div>
        <div><strong>Limitations:</strong> ${escapeText(limitationsText, "")}</div>
    `).show()
}

function renderExecutiveCards($container, items, buildCardHtml) {
    $container.empty()
    if (!items.length) {
        $container.append('<div class="ui message">No findings to display.</div>')
        return
    }
    items.forEach(item => {
        $container.append(buildCardHtml(item))
    })
}

function renderExecutiveView() {
    const $executiveView = $('#executive_view')
    if (!$executiveView.length) return
    if (!exportModelReady && !hasExportData()) {
        return
    }
    const filtered = getFilteredExportModel()
    const model = buildReportModel(filtered, { preset: "executive" })
    const severityCounts = model.summary?.bySeverity || {}
    const context = model.meta.context || {}

    const tiers = (() => {
        const correlated = model.correlation || []
        let confirmed = 0
        let likely = 0
        const correlatedIds = new Set()
        correlated.forEach(group => {
            const engines = group.engines || []
            const hasDastOrIast = engines.includes("DAST") || engines.includes("IAST")
            if (hasDastOrIast) confirmed += 1
            else likely += 1
            group.instances?.forEach(instance => {
                if (instance?.findingId) correlatedIds.add(instance.findingId)
            })
        })
        const potential = model.findings.filter(item => item?.findingId && !correlatedIds.has(item.findingId)).length
        const confirmedHigh = model.findings.filter(item => {
            const sev = normalizeSeverityKey(item.severity)
            return (sev === "critical" || sev === "high") && correlatedIds.has(item.findingId)
        }).length
        return { confirmed, likely, potential, confirmedHigh }
    })()

    const conclusion = buildExecutiveConclusion(model, tiers)
    const $summary = $('#summary_segment .ui.placeholder.segment')
    $summary.find('.exec-conclusion-line').remove()
    $summary.prepend(`<div class="ui tiny grey text exec-conclusion-line" style="margin-bottom: 8px;">${escapeText(conclusion)}</div>`)

    const topLabel = buildTopRisksLabel(severityCounts)
    const topPool = severityCounts.critical > 0
        ? model.findings.filter(item => normalizeSeverityKey(item?.severity) === "critical")
        : model.findings
    const topGrouped = groupFindingsForExec(topPool, {
        keyFn: item => item.title || item.findingId || "finding",
        maxItems: 5
    })

    renderExecutiveCards($('#exec_top_risks_content'), topGrouped, entry => {
        const item = entry.item
        const severityKey = normalizeSeverityKey(item.severity)
        const asset = formatAssetForOverview(item.location)
        const owner = inferOwnerHint(item)
        const occ = entry.count > 1 ? ` - ${entry.count} occurrences` : ""
        const mappingSection = renderMappingSection(item.cwe, resolveOwaspList(item))
        return `
            <div class="ui card">
                <div class="content">
                    <div class="header">${escapeText(item.title)}${occ ? escapeText(occ, "") : ""}</div>
                    <div class="meta">${escapeText(item.engine || "")} • ${escapeText(asset || "N/A")}</div>
                    <div class="description" style="margin-top: 6px;">
                        <span class="finding-severity-badge ${severityKey}">${escapeText(severityKey)}</span>
                        <span style="margin-left: 8px;">Owner: ${escapeText(owner)}</span>
                    </div>
                    ${mappingSection ? `<div style="margin-top: 8px;"></div>${mappingSection}` : ""}
                </div>
            </div>
        `
    })
    $('#exec_top_risks .exec-section-title-text').text(topLabel)
    $('#exec_top_risks').toggle(topGrouped.length > 0)

    const correlated = (model.correlation || [])
        .slice()
        .sort((a, b) => {
            const sev = severityRank(a.maxSeverity) - severityRank(b.maxSeverity)
            if (sev !== 0) return sev
            const aHasRuntime = (a.engines || []).includes("DAST") || (a.engines || []).includes("IAST")
            const bHasRuntime = (b.engines || []).includes("DAST") || (b.engines || []).includes("IAST")
            if (aHasRuntime !== bHasRuntime) return aHasRuntime ? -1 : 1
            return (b.combinedConfidence || 0) - (a.combinedConfidence || 0)
        })
        .slice(0, 10)
    renderExecutiveCards($('#exec_correlated_content'), correlated, group => {
        const severityKey = normalizeSeverityKey(group.maxSeverity || "info")
        const engines = group.engines?.join(", ") || ""
        const routes = (group.sampleUrls || []).map(url => formatUrlForTable(url, "overview")).join(" | ")
        const reason = buildCorrelationReason(group)
        return `
            <div class="ui card">
                <div class="content">
                    <div class="header">${escapeText(group.title)}</div>
                    <div class="meta">${escapeText(engines)}</div>
                    <div class="description" style="margin-top: 6px;">
                        <span class="finding-severity-badge ${severityKey}">${escapeText(severityKey)}</span>
                        <span style="margin-left: 8px;">Confidence: ${escapeText(Math.round(group.combinedConfidence || 0))}</span>
                        <span style="margin-left: 8px;">Assets: ${escapeText(group.affectedAssetsCount || 0)}</span>
                    </div>
                    <div class="description" style="margin-top: 6px; color: rgba(0,0,0,0.6);">
                        Impacted routes: ${escapeText(routes || "N/A")}
                    </div>
                    <div class="description" style="margin-top: 6px; color: rgba(0,0,0,0.6);">
                        Why high confidence: ${escapeText(reason)}
                    </div>
                </div>
            </div>
        `
    })
    if (correlated.length === 1) {
        $('#exec_correlated .exec-section-title-text').text("1 correlated issue found")
    } else {
        $('#exec_correlated .exec-section-title-text').text("Correlated Findings")
    }
    $('#exec_correlated').toggle(correlated.length > 0)

    const execSections = [
        { id: "dast", label: "DAST", container: "#exec_dast_top", content: "#exec_dast_top_content" },
        { id: "iast", label: "IAST", container: "#exec_iast_top", content: "#exec_iast_top_content" },
        { id: "sast", label: "SAST", container: "#exec_sast_top", content: "#exec_sast_top_content" },
        { id: "sca", label: "SCA", container: "#exec_sca_top", content: "#exec_sca_top_content" }
    ]
    execSections.forEach(section => {
        const findings = model.sections?.[section.id] || []
        const grouped = groupFindingsForExec(findings, {
            keyFn: section.id === "sca"
                ? normalizeScaKey
                : (item) => item.title || item.findingId || "finding"
        })
        renderExecutiveCards($(section.content), grouped, entry => {
            const item = entry.item
            const severityKey = normalizeSeverityKey(item.severity)
            const asset = formatAssetForOverview(item.location)
            const description = item.description ? sanitizeRichText(item.description) : ""
            const fix = item.recommendation ? sanitizeRichText(item.recommendation) : escapeText(inferFix(item))
            const occ = entry.count > 1 ? ` - ${entry.count} occurrences` : ""
            const mappingSection = renderMappingSection(item.cwe, resolveOwaspList(item))
            const referencesSection = renderReferenceLinks(item.references || {})
            return `
                <div class="ui card">
                    <div class="content">
                        <div class="header">${escapeText(item.title)}${occ ? escapeText(occ, "") : ""}</div>
                        <div class="meta">${escapeText(asset || "N/A")}</div>
                        <div class="description" style="margin-top: 6px;">
                            <span class="finding-severity-badge ${severityKey}">${escapeText(severityKey)}</span>
                        </div>
                        ${description ? `<div class="sast-section" style="margin-top: 8px;"><div class="sast-section-title"><strong>Description</strong></div>${description}</div>` : ""}
                        <div class="sast-section" style="margin-top: 8px;"><div class="sast-section-title"><strong>Recommendation</strong></div>${fix}</div>
                        ${mappingSection}
                        ${referencesSection}
                    </div>
                </div>
            `
        })
        $(section.container).toggle(grouped.length > 0)
    })

    // Build Exposure & Hygiene content for summary
    const headerHighlights = (model.dashboard.owaspHeaders || []).slice(0, 3)
    const headersText = headerHighlights.length
        ? headerHighlights.join("; ")
        : "No header issues detected or data unavailable."
    const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
    const tokenInStorage = [...(storageDetails.localStorage || []), ...(storageDetails.sessionStorage || [])]
        .some(entry => STORAGE_TOKEN_KEY_REGEX.test(String(entry.key)))
    const cookieFlagsMissing = (model.dashboard.cookies || []).some(item => item?.httpOnly === false)
    const tokenLine = `Tokens in storage: ${tokenInStorage ? "Yes" : "No"}; Cookie HttpOnly missing: ${cookieFlagsMissing ? "Yes" : "No"}`
    const scaTop = (model.sections?.sca || []).slice(0, 3).map(item => {
        const fix = item.recommendation ? truncateSnippet(item.recommendation, 80) : "Upgrade to a secure version."
        return `${item.title} (${item.severity}) - ${fix}`
    })
    const scaLine = scaTop.length ? scaTop.join("; ") : "No high-risk dependencies identified or data unavailable."

    // Populate Exposure & Hygiene in summary
    $('#summary_exposure_content').html(`
        <p><strong>Headers:</strong> ${escapeText(headersText)}</p>
        <p><strong>Token/storage:</strong> ${escapeText(tokenLine)}</p>
        <p><strong>Dependencies:</strong> ${escapeText(scaLine)}</p>
    `)

    // Populate Remediation Plan in summary
    renderSummaryRemediation(severityCounts)

    // Show executive extras in summary
    $('#summary_executive_extras').show()

    updateMethodologyFooter(model, { preset: "executive" })
}

function renderTechnicalCorrelatedFindings() {
    const correlationGroups = buildCorrelationGroups(exportModel.findings)
    const correlated = correlationGroups
        .slice()
        .sort((a, b) => {
            const sev = severityRank(a.maxSeverity) - severityRank(b.maxSeverity)
            if (sev !== 0) return sev
            const aHasRuntime = (a.engines || []).includes("DAST") || (a.engines || []).includes("IAST")
            const bHasRuntime = (b.engines || []).includes("DAST") || (b.engines || []).includes("IAST")
            if (aHasRuntime !== bHasRuntime) return aHasRuntime ? -1 : 1
            return (b.combinedConfidence || 0) - (a.combinedConfidence || 0)
        })
        .slice(0, 10)

    const $content = $('#tech_correlated_content')
    $content.empty()

    correlated.forEach(group => {
        const severityKey = normalizeSeverityKey(group.maxSeverity || "info")
        const engines = group.engines?.join(", ") || ""
        const routes = (group.sampleUrls || []).map(url => formatUrlForTable(url, "overview")).join(" | ")
        const reason = buildCorrelationReason(group)
        const cardHtml = `
            <div class="ui card">
                <div class="content">
                    <div class="header">${escapeText(group.title)}</div>
                    <div class="meta">${escapeText(engines)}</div>
                    <div class="description" style="margin-top: 6px;">
                        <span class="finding-severity-badge ${severityKey}">${escapeText(severityKey)}</span>
                        <span style="margin-left: 8px;">Confidence: ${escapeText(Math.round(group.combinedConfidence || 0))}</span>
                        <span style="margin-left: 8px;">Assets: ${escapeText(group.affectedAssetsCount || 0)}</span>
                    </div>
                    <div class="description" style="margin-top: 6px; color: rgba(0,0,0,0.6);">
                        Impacted routes: ${escapeText(routes || "N/A")}
                    </div>
                    <div class="description" style="margin-top: 6px; color: rgba(0,0,0,0.6);">
                        Why high confidence: ${escapeText(reason)}
                    </div>
                </div>
            </div>
        `
        $content.append(cardHtml)
    })

    if (correlated.length === 1) {
        $('#tech_correlated .tech-section-title-text').text("1 correlated issue found")
    } else {
        $('#tech_correlated .tech-section-title-text').text("Correlated Findings")
    }
    $('#tech_correlated').toggle(correlated.length > 0)
}

function setReportView(preset) {
    const mode = preset || "technical"
    const isExecutive = mode === "executive"
    $('#executive_view').toggle(isExecutive)
    $('#technical_view').toggle(!isExecutive)
    $('#summary_executive_extras').show()
    updateSummarySegment()
    if (isExecutive) {
        renderExecutiveView()
    } else {
        renderTechnicalCorrelatedFindings()
        updateMethodologyFooter(null, { preset: "technical" })
    }
}

function recomputeSummary() {
    const byEngine = {}
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    exportModel.findings.forEach(finding => {
        const engine = finding.engine || "UNKNOWN"
        byEngine[engine] = (byEngine[engine] || 0) + 1
        const severity = normalizeExportSeverity(finding.severity)
        bySeverity[severity] = (bySeverity[severity] || 0) + 1
    })
    exportModel.summary = { byEngine, bySeverity }
    updateSummarySegment()
    renderExecutiveView()
    renderTechnicalCorrelatedFindings()
    updateMethodologyFooter(null, { preset: $('#report_preset').val() || "technical" })
}

function replaceFindingsForEngine(engine, findings) {
    exportModel.findings = exportModel.findings.filter(item => item.engine !== engine)
    exportModel.findings = exportModel.findings.concat(findings)
    recomputeSummary()
    updateExportButtons()
}

function replaceSectionFindings(sectionId, findings) {
    exportModel.sections[sectionId] = findings
    const engine = sectionId === "dast" ? "DAST" : sectionId.toUpperCase()
    exportModel.findings = exportModel.findings.filter(item => item.engine !== engine)
    exportModel.findings = exportModel.findings.concat(findings)
    recomputeSummary()
    updateExportButtons()
}

function safeJsonParse(value) {
    try {
        return JSON.parse(value)
    } catch (_) {
        return null
    }
}

function normalizeStorageEntries(value) {
    if (!value || typeof value !== "object") return []
    const entries = []
    Object.keys(value).forEach(key => {
        if (/^ptk_/i.test(key)) return
        const raw = value[key]
        let display = raw
        if (raw && typeof raw === "object") {
            try {
                display = JSON.stringify(raw)
            } catch (_) {
                display = String(raw)
            }
        }
        entries.push({ key, value: display })
    })
    return entries
}

function stripHtmlTags(value) {
    if (!value) return ""
    const text = String(value)
    try {
        if (typeof DOMParser !== "undefined") {
            const doc = new DOMParser().parseFromString(text, "text/html")
            return doc?.body?.textContent || ""
        }
    } catch (_) {
        // Fall back to iterative regex stripping if DOMParser is unavailable.
    }
    let prev = text
    let next = prev.replace(/<[^>]*>/g, "")
    while (next !== prev) {
        prev = next
        next = prev.replace(/<[^>]*>/g, "")
    }
    return next
}

function updateExportDashboardModel() {
    const tab = index_controller?.tab || {}
    exportModel.dashboard.technologies = Array.isArray(tab.technologies)
        ? tab.technologies.map(item => ({
            name: item?.name || "",
            version: item?.version || "",
            category: item?.category || ""
        }))
        : []
    exportModel.dashboard.owaspHeaders = Array.isArray(tab.findings)
        ? tab.findings.map(item => (Array.isArray(item) ? item[0] : item)).filter(Boolean)
        : []
    exportModel.dashboard.cves = Array.isArray(tab.cves)
        ? tab.cves.map(item => {
            const evidence = item?.evidence || {}
            return {
                id: item?.id || item?.title || "",
                severity: item?.severity || "",
                evidence: `H:${evidence.headers || 0} / HTML:${evidence.html || 0} / JS:${evidence.js || 0}`,
                verify: item?.verify?.moduleId ? `DAST module: ${item.verify.moduleId}` : ""
            }
        })
        : []
    exportModel.dashboard.headers = tab.requestHeaders && typeof tab.requestHeaders === "object"
        ? Object.keys(tab.requestHeaders)
            .filter(name => name.startsWith('x-') || name === 'authorization' || name === 'cookie')
            .map(name => ({ name, value: tab.requestHeaders[name]?.[0] || "" }))
        : []
    exportModel.dashboard.cookies = tab.cookies && typeof tab.cookies === "object"
        ? Object.values(tab.cookies).map(item => ({
            domain: item?.domain || "",
            name: item?.name || "",
            value: item?.value || "",
            httpOnly: item?.httpOnly ?? ""
        }))
        : []
    exportModel.dashboard.storage = tab.storage && typeof tab.storage === "object"
        ? Object.keys(tab.storage).map(key => {
            const parsed = safeJsonParse(tab.storage[key])
            const container = parsed && typeof parsed === "object" && parsed[key]
                ? parsed[key]
                : parsed
            const count = container && typeof container === "object" ? Object.keys(container).length : 0
            return { type: key, entriesCount: count }
        })
        : []
    const storageDetails = { localStorage: [], sessionStorage: [] }
    if (tab.storage && typeof tab.storage === "object") {
        ["localStorage", "sessionStorage"].forEach(key => {
            const parsed = safeJsonParse(tab.storage[key])
            const container = parsed && typeof parsed === "object" && parsed[key]
                ? parsed[key]
                : parsed
            storageDetails[key] = normalizeStorageEntries(container)
        })
    }
    exportModel.dashboard.storageDetails = storageDetails
    exportModel.dashboard.tokens = Array.isArray(tokens)
        ? tokens.map(entry => ({
            source: entry?.[0] || "",
            payload: stripHtmlTags(entry?.[1] || ""),
            token: entry?.[2] || ""
        }))
        : []
}

function buildExportFindingFromNormalized(finding, viewModel) {
    const engine = finding?.engine || "UNKNOWN"
    const location = finding?.location || {}
    const references = buildReferenceList(finding?.links)
    const exportFinding = {
        engine,
        severity: normalizeExportSeverity(finding?.severity),
        confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null,
        title: finding?.ruleName || finding?.vulnId || finding?.category || "Finding",
        description: finding?.description || finding?.metadata?.description || finding?.module_metadata?.description || "",
        recommendation: finding?.recommendation || finding?.metadata?.recommendation || finding?.module_metadata?.recommendation || "",
        location: {
            url: location?.url || null,
            route: location?.route || null,
            file: location?.file || null,
            line: location?.line ?? null,
            column: location?.column ?? null,
            param: location?.param || null
        },
        evidence: {
            requestSnippet: "",
            responseSnippet: "",
            codeSnippet: "",
            notes: "",
            evidenceFullAvailable: false
        },
        references,
        cwe: Array.isArray(finding?.cwe) ? finding.cwe : (finding?.cwe ? [finding.cwe] : []),
        owasp: resolveOwaspList(finding)
    }

    if (engine === "DAST") {
        const { requestRecord, attackRecord } = resolveDastAttackContext(finding, viewModel)
        const requestRaw = attackRecord?.request?.raw || requestRecord?.original?.request?.raw || ""
        const responseRaw = attackRecord?.response?.raw
            || (attackRecord?.response ? buildRawResponse(attackRecord.response) : "")
            || (requestRecord?.original?.response ? buildRawResponse(requestRecord.original.response) : "")
        const proof = attackRecord?.proof || finding?.evidence?.dast?.proof || ""
        const meta = attackRecord?.metadata || finding?.metadata || {}
        exportFinding.evidence.requestSnippet = truncateSnippet(requestRaw)
        exportFinding.evidence.responseSnippet = truncateSnippet(responseRaw)
        exportFinding.evidence.notes = truncateSnippet(proof)
        exportFinding.evidence.evidenceFullAvailable = !!(requestRaw || responseRaw)
        if (!exportFinding.description) {
            exportFinding.description = meta.description || ""
        }
        if (!exportFinding.recommendation) {
            exportFinding.recommendation = meta.recommendation || ""
        }
        if (!exportFinding.references.length && meta.links) {
            exportFinding.references = buildReferenceList(meta.links)
        }
        if (meta.owasp) {
            const metaOwasp = normalizeOwaspEntries(meta.owasp)
            const hasVersioned = metaOwasp.some(entry => /\d{4}/.test(entry))
            if (metaOwasp.length && (hasVersioned || !exportFinding.owasp.length)) {
                exportFinding.owasp = metaOwasp
            }
        }
        if (!exportFinding.cwe.length && meta.cwe) {
            exportFinding.cwe = normalizeCweEntries(meta.cwe)
        }
    } else if (engine === "SAST") {
        const codeSnippet = finding?.evidence?.sast?.codeSnippet || ""
        exportFinding.evidence.codeSnippet = truncateSnippet(codeSnippet)
        exportFinding.evidence.notes = truncateSnippet(finding?.evidence?.sast?.nodeType || "")
        exportFinding.evidence.trace = normalizeTraceForExport(finding?.evidence?.sast?.trace || "")
        exportFinding.evidence.source = normalizeEndpointDetails(finding?.evidence?.sast?.source || null)
        exportFinding.evidence.sink = normalizeEndpointDetails(finding?.evidence?.sast?.sink || null)
        exportFinding.evidence.evidenceFullAvailable = !!(finding?.evidence?.sast?.trace || codeSnippet)
    } else if (engine === "IAST") {
        const iastEvidence = finding?.evidence?.iast || {}
        const context = iastEvidence?.context || {}
        const iastSnippet = context?.valuePreview || context?.location || ""
        exportFinding.evidence.codeSnippet = truncateSnippet(iastSnippet)
        const message = iastEvidence?.message || iastEvidence?.flowSummary || ""
        exportFinding.evidence.notes = truncateSnippet(message)
        exportFinding.evidence.proof = truncateSnippet(resolveIastProof(iastEvidence, context))
        exportFinding.evidence.flow = normalizeIastFlowForExport(iastEvidence?.flow || context?.flow || "")
        exportFinding.evidence.trace = normalizeTraceForExport(iastEvidence?.trace || "")
        exportFinding.evidence.source = iastEvidence?.taintSource || iastEvidence?.sourceId || ""
        exportFinding.evidence.sink = iastEvidence?.sinkId || ""
        exportFinding.evidence.url = iastEvidence?.routing?.runtimeUrl || iastEvidence?.routing?.url || finding?.location?.url || ""
        exportFinding.evidence.category = finding?.category || ""
        exportFinding.evidence.evidenceFullAvailable = !!(iastEvidence?.trace || iastSnippet)
    }

    return exportFinding
}

function buildExportFindingFromSca(entry) {
    const component = entry?.component || {}
    const finding = entry?.finding || {}
    const componentName = component.component || component.name || component.library || component.package || component.module || "Unknown component"
    const componentVersion = component.version || component.pkgVersion || component.release || component.componentVersion || component.libraryVersion || component.packageVersion || ""
    const description = finding.description || finding?.identifiers?.description || ""
    const recommendation = finding.recommendation || finding?.identifiers?.recommendation || ""
    const references = normalizeScaList(finding?.info || finding?.references || finding?.urls)
        .map(url => ({ title: null, url }))
        .filter(entry => entry.url)
    return {
        engine: "SCA",
        severity: normalizeExportSeverity(finding?.severity),
        confidence: 85,
        title: `${componentName} - ${finding?.identifiers?.summary || finding?.summary || "Vulnerability"}`,
        componentName,
        componentVersion,
        description,
        location: {
            file: component.file || component.path || component.location || null
        },
        evidence: {
            requestSnippet: "",
            responseSnippet: "",
            codeSnippet: truncateSnippet(description || recommendation),
            notes: truncateSnippet(recommendation),
            evidenceFullAvailable: !!(description || recommendation)
        },
        references,
        cwe: Array.isArray(finding?.cwe) ? finding.cwe : (finding?.cwe ? [finding.cwe] : []),
        owasp: []
    }
}

function escapeMarkdownCell(value) {
    if (value === null || value === undefined) return ""
    const escaped = escapeMarkdownText(String(value))
    return escaped.replace(/\|/g, "\\|").replace(/\n/g, " ").replace(/\r/g, " ")
}

function escapeMarkdownText(value) {
    if (value === null || value === undefined) return ""
    return String(value)
        .replace(/\\/g, "\\\\")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
}

function toMarkdownTable(headers, rows) {
    const headerLine = `| ${headers.map(escapeMarkdownCell).join(" | ")} |`
    const sepLine = `| ${headers.map(() => "---").join(" | ")} |`
    const bodyLines = rows.map(row => `| ${row.map(escapeMarkdownCell).join(" | ")} |`)
    return [headerLine, sepLine, ...bodyLines].join("\n")
}

function buildMarkdownFromExportModel(model) {
    const lines = []
    const push = (line = "") => lines.push(line)
    const host = model.meta.host || "unknown"
    const reportType = model.meta.reportType || "report"
    const generatedAt = model.meta.generatedAt || new Date().toISOString()
    const isExecutive = model.meta.preset === "executive"

    push(`# OWASP PTK Security Report`)
    push(``)
    push(`- Host: ${escapeMarkdownText(host)}`)
    push(`- Report type: ${escapeMarkdownText(reportType)}`)
    push(`- Generated: ${escapeMarkdownText(generatedAt)}`)
    push(``)

    // Summary section (both presets)
    if (Object.keys(model.summary.byEngine || {}).length) {
        push(`## Summary`)
        push(``)
        push(`### Risk Ratings`)
        const severityRows = Object.entries(model.summary.bySeverity || {})
            .map(([severity, count]) => [severity, count])
        if (severityRows.length) {
            push(toMarkdownTable(["Severity", "Count"], severityRows))
            push(``)
        }
        push(`### Findings by Engine`)
        const engineRows = Object.entries(model.summary.byEngine).map(([engine, count]) => [engine, count])
        if (engineRows.length) {
            push(toMarkdownTable(["Engine", "Count"], engineRows))
            push(``)
        }

        // Exposure & Hygiene in Summary
        push(`### Exposure & Hygiene`)
        const headerHighlights = (model.dashboard.owaspHeaders || []).slice(0, 3)
        const headersText = headerHighlights.length
            ? headerHighlights.join("; ")
            : "No header issues detected or data unavailable."
        const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
        const tokenInStorage = [...(storageDetails.localStorage || []), ...(storageDetails.sessionStorage || [])]
            .some(entry => STORAGE_TOKEN_KEY_REGEX.test(String(entry.key)))
        const cookieFlagsMissing = (model.dashboard.cookies || []).some(item => item?.httpOnly === false)
        push(`- **Headers:** ${escapeMarkdownText(headersText)}`)
        push(`- **Token/storage:** ${escapeMarkdownText(`Tokens in storage: ${tokenInStorage ? "Yes" : "No"}; Cookie HttpOnly missing: ${cookieFlagsMissing ? "Yes" : "No"}`)}`)
        const scaTop = (model.sections?.sca || []).slice(0, 3).map(item => {
            const fix = item.recommendation ? truncateSnippet(item.recommendation, 80) : "Upgrade to a secure version."
            return `${item.title} (${item.severity}) - ${fix}`
        })
        const scaLine = scaTop.length ? scaTop.join("; ") : "No high-risk dependencies identified or data unavailable."
        push(`- **Dependencies:** ${escapeMarkdownText(scaLine)}`)
        push(``)

        // Remediation Plan in Summary
        push(`### Remediation Plan`)
        const sev = model.summary.bySeverity || {}
        push(toMarkdownTable(["Bucket", "Items"], [
            ["Fix now (0–7 days)", (sev.critical || 0) + (sev.high || 0)],
            ["Fix soon (7–30 days)", sev.medium || 0],
            ["Backlog", (sev.low || 0) + (sev.info || 0)]
        ]))
        push(``)
    }

    if (isExecutive) {
        // Executive format: Top 5 Highest Risks, Correlated, then engine sections
        const topLabel = buildTopRisksLabel(model.summary?.bySeverity || {})
        const severityCounts = model.summary?.bySeverity || {}
        const topPool = severityCounts.critical > 0
            ? model.findings.filter(item => normalizeSeverityKey(item?.severity) === "critical")
            : model.findings
        const topGrouped = groupFindingsForExec(topPool, {
            keyFn: item => item.title || item.findingId || "finding",
            maxItems: 5
        })

        if (topGrouped.length) {
            push(`## ${topLabel}`)
            push(``)
            // Render each finding as a card-like block (matching HTML layout)
            topGrouped.forEach(entry => {
                const item = entry.item
                const occ = entry.count > 1 ? ` (${entry.count} occurrences)` : ""
                const owner = inferOwnerHint(item)
                const mapping = renderMappingSectionMarkdown(item.cwe, resolveOwaspList(item))
                const refs = buildReferenceSummary(item)
                const asset = formatAssetForOverview(item.location)
                const severityKey = normalizeSeverityKey(item.severity)

                push(`### ${escapeMarkdownText(item.title)}${occ}`)
                push(`${escapeMarkdownText(item.engine || "DAST")} • ${escapeMarkdownText(asset)}`)
                push(``)
                push(`**${severityKey.toUpperCase()}** | Owner: ${escapeMarkdownText(owner)}`)
                push(``)
                const cweList = Array.isArray(item.cwe) ? item.cwe : (item.cwe ? [item.cwe] : [])
                const owaspList = resolveOwaspList(item)
                if (cweList.length) {
                    push(`**CWE:**`)
                    push(escapeMarkdownText(cweList.join(", ")))
                    push(``)
                }
                if (owaspList.length) {
                    push(`**OWASP:**`)
                    push(escapeMarkdownText(owaspList.join(", ")))
                    push(``)
                }
                if (item.references?.length) {
                    push(`**References:**`)
                    item.references.slice(0, 5).forEach(ref => {
                        const refUrl = ref?.url || ref
                        if (refUrl) push(escapeMarkdownText(refUrl))
                    })
                    push(``)
                }
                push(``)
                push(`---`)
                push(``)
            })
        }

        // Correlated Findings
        const correlated = (model.correlation || []).slice(0, 10)
        if (correlated.length) {
            const correlationTitle = correlated.length === 1 ? "1 correlated issue found" : "Correlated Findings"
            push(`## ${correlationTitle}`)
            push(``)
            // Render each correlated finding as a card-like block (matching HTML layout)
            correlated.forEach(group => {
                const severityKey = normalizeSeverityKey(group.maxSeverity || "info")
                const engines = group.engines?.join(", ") || ""
                const routes = (group.sampleUrls || []).map(url => formatUrlForTable(url, "overview")).join(", ")
                const reason = buildCorrelationReason(group)

                push(`### ${escapeMarkdownText(group.title)}`)
                push(`${escapeMarkdownText(engines)}`)
                push(``)
                push(`**${severityKey.toUpperCase()}** | Confidence: ${Math.round(group.combinedConfidence || 0)} | Assets: ${group.affectedAssetsCount || 0}`)
                push(``)
                if (routes) {
                    push(`Impacted routes: ${escapeMarkdownText(routes)}`)
                }
                if (reason) {
                    push(`Why high confidence: ${escapeMarkdownText(reason)}`)
                }
                push(``)
                push(`---`)
                push(``)
            })
        }

        // Engine Top Findings (executive format) - card-like blocks matching HTML
        const engineSections = [
            { id: "dast", label: "DAST" },
            { id: "iast", label: "IAST" },
            { id: "sast", label: "SAST" },
            { id: "sca", label: "SCA" }
        ]
        engineSections.forEach(section => {
            const findings = model.sections?.[section.id] || []
            if (!findings.length) return
            const grouped = groupFindingsForExec(findings, {
                keyFn: section.id === "sca"
                    ? normalizeScaKey
                    : (item) => item.title || item.findingId || "finding"
            })
            push(`## ${section.label} Top Findings`)
            push(``)

            // Render each finding as a card-like block
            grouped.forEach(entry => {
                const item = entry.item
                const occ = entry.count > 1 ? ` - ${entry.count} occurrences` : ""
                const asset = formatAssetForOverview(item.location)
                const severityKey = normalizeSeverityKey(item.severity)
                const description = item.description ? stripHtmlToText(item.description) : ""
                const fix = item.recommendation ? stripHtmlToText(item.recommendation) : inferFix(item)

                push(`### ${escapeMarkdownText(item.title)}${occ}`)
                push(`${escapeMarkdownText(asset)}`)
                push(``)
                push(`**${severityKey.toUpperCase()}**`)
                push(``)

                // Description (for DAST/IAST/SAST, not SCA)
                if (description && section.id !== "sca") {
                    push(`**Description:**`)
                    push(escapeMarkdownText(description))
                    push(``)
                }

                // Fix/Recommendation
                if (fix) {
                    push(`**Recommendation:**`)
                    push(escapeMarkdownText(fix))
                    push(``)
                }

                // CWE (separate from OWASP)
                const cweList = Array.isArray(item.cwe) ? item.cwe : (item.cwe ? [item.cwe] : [])
                if (cweList.length) {
                    push(`**CWE:**`)
                    push(escapeMarkdownText(cweList.join(", ")))
                    push(``)
                }

                // OWASP (separate from CWE)
                const owaspList = resolveOwaspList(item)
                if (owaspList.length) {
                    push(`**OWASP:**`)
                    push(escapeMarkdownText(owaspList.join(", ")))
                    push(``)
                }

                // References (each on separate line)
                const refsList = (item.references || []).map(ref => ref?.url || ref).filter(Boolean)
                if (refsList.length) {
                    push(`**References:**`)
                    refsList.forEach(refUrl => {
                        push(escapeMarkdownText(refUrl))
                    })
                    push(``)
                }
                push(`---`)
                push(``)
            })
        })

        // Methodology & Scope (footer)
        push(``)
        push(`Report generated using OWASP PTK scanning engines. Executive preset includes top findings only and excludes sensitive evidence by default. Results depend on scan coverage and target responsiveness.`)
        const scopeText = model.meta.context?.scopeSummary && model.meta.context?.scopeSummary !== "N/A"
            ? model.meta.context.scopeSummary
            : "N/A"
        push(`**Scope:** ${escapeMarkdownText(scopeText)}`)
        push(`**Limitations:** Results depend on available routes and auth context; some flows may not be covered.`)
        push(``)

    } else {
        // Technical format aligned with HTML sections
        push(`## General Information`)
        push(``)
        if (model.dashboard.technologies.length) {
            push(`### Technology Stack`)
            const rows = model.dashboard.technologies.map(item => [item.name, item.version, item.category])
            push(toMarkdownTable(["Name", "Version", "Category"], rows))
            push(``)
        }

        if (model.dashboard.owaspHeaders.length) {
            push(`### OWASP Secure Headers`)
            const rows = model.dashboard.owaspHeaders.map(item => [item])
            push(toMarkdownTable(["Header"], rows))
            push(``)
        }

        if (model.dashboard.cves.length) {
            push(`### CVE Lookup`)
            const rows = model.dashboard.cves.map(item => [item.id, item.severity, item.evidence, item.verify])
            push(toMarkdownTable(["CVE", "Severity", "Evidence", "Verify"], rows))
            push(``)
        }

        if (model.dashboard.headers.length) {
            push(`### Request Headers`)
            const rows = model.dashboard.headers.map(item => [item.name, item.value])
            push(toMarkdownTable(["Header", "Value"], rows))
            push(``)
        }

        if (model.dashboard.cookies.length) {
            push(`### Cookies`)
            const rows = model.dashboard.cookies.map(item => [item.domain, item.name, item.value, String(item.httpOnly)])
            push(toMarkdownTable(["Domain", "Name", "Value", "HttpOnly"], rows))
            push(``)
        }

        const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
        if (storageDetails.localStorage.length) {
            push(`### Local Storage`)
            const rows = storageDetails.localStorage.map(item => [item.key, truncateSnippet(item.value, 400)])
            push(toMarkdownTable(["Key", "Value"], rows))
            push(``)
        }
        if (storageDetails.sessionStorage.length) {
            push(`### Session Storage`)
            const rows = storageDetails.sessionStorage.map(item => [item.key, truncateSnippet(item.value, 400)])
            push(toMarkdownTable(["Key", "Value"], rows))
            push(``)
        }
        if (model.dashboard.storage.length && !storageDetails.localStorage.length && !storageDetails.sessionStorage.length) {
            push(`### Storage`)
            const rows = model.dashboard.storage.map(item => [item.type, item.entriesCount])
            push(toMarkdownTable(["Storage", "Entries"], rows))
            push(``)
        }

        // Correlated Findings section (if any exist)
        const correlationGroups = model.correlation || buildCorrelationGroups(model.findings)
        if (correlationGroups && correlationGroups.length) {
            const correlationTitle = correlationGroups.length === 1 ? "1 correlated issue found" : "Correlated Findings"
            push(`## ${correlationTitle}`)
            push(``)
            const sortedCorrelation = correlationGroups.slice().sort((a, b) => {
                const sev = severityRank(a.maxSeverity) - severityRank(b.maxSeverity)
                if (sev !== 0) return sev
                const aHasRuntime = (a.engines || []).includes("DAST") || (a.engines || []).includes("IAST")
                const bHasRuntime = (b.engines || []).includes("DAST") || (b.engines || []).includes("IAST")
                if (aHasRuntime !== bHasRuntime) return aHasRuntime ? -1 : 1
                return (b.combinedConfidence || 0) - (a.combinedConfidence || 0)
            })
            sortedCorrelation.slice(0, 10).forEach(group => {
                const severityKey = normalizeSeverityKey(group.maxSeverity || "info")
                const engines = group.engines?.join(", ") || ""
                const routes = (group.sampleUrls || []).map(url => formatUrlForTable(url, "overview")).join(", ")
                const reason = buildCorrelationReason(group)

            push(`### ${escapeMarkdownText(group.title)}`)
            push(`${escapeMarkdownText(engines)}`)
            push(``)
            push(`**${severityKey.toUpperCase()}** | Confidence: ${Math.round(group.combinedConfidence || 0)} | Assets: ${group.affectedAssetsCount || 0}`)
            push(``)
            if (routes) {
                push(`Impacted routes: ${escapeMarkdownText(routes)}`)
            }
            if (reason) {
                push(`Why high confidence: ${escapeMarkdownText(reason)}`)
            }
                push(``)
                push(`---`)
                push(``)
            })
        }

        const sections = [
            { id: "dast", label: "DAST" },
            { id: "iast", label: "IAST" },
            { id: "sast", label: "SAST" },
            { id: "sca", label: "SCA" }
        ]
        sections.forEach(section => {
            const findings = model.sections?.[section.id] || []
            if (!findings.length) return
            push(`## ${section.label}`)
            push(``)

            // Render each finding as a card-like block (similar to executive report)
            findings.forEach(item => {
                const severityKey = normalizeSeverityKey(item.severity)
                const confidence = item.confidence != null ? ` | Confidence: ${Math.round(item.confidence)}` : ""
                const location = formatLocationSummary(item.location)
                const description = item.description ? stripHtmlToText(item.description) : ""
                const fix = item.recommendation ? stripHtmlToText(item.recommendation) : ""
                const evidence = item.evidence || {}

                push(`### ${escapeMarkdownText(item.findingId || section.label)} - ${escapeMarkdownText(item.title)}`)
                if (location) {
                    push(`${escapeMarkdownText(location)}`)
                }
                push(``)
                push(`**${severityKey.toUpperCase()}**${confidence}`)
                push(``)

                const renderOtherInfo = () => {
                    if (description && section.id !== "sca") {
                        push(`**Description:**`)
                        push(escapeMarkdownText(truncateSnippet(description, 1200)))
                        push(``)
                    }
                    if (fix) {
                        push(`**Recommendation:**`)
                        push(escapeMarkdownText(truncateSnippet(fix, 800)))
                        push(``)
                    }
                    if (item.cwe?.length) {
                        push(`**CWE:**`)
                        push(escapeMarkdownText(item.cwe.join(", ")))
                        push(``)
                    }
                    if (item.owasp?.length) {
                        const owaspLabel = item.owasp.map(entry => (typeof entry === "string" ? entry : entry?.name || entry?.id || "")).filter(Boolean).join(", ")
                        if (owaspLabel) {
                            push(`**OWASP:**`)
                            push(escapeMarkdownText(owaspLabel))
                            push(``)
                        }
                    }
                    if (item.references?.length) {
                        push(`**References:**`)
                        item.references.slice(0, 5).forEach(ref => {
                            const refUrl = ref?.url || ref
                            if (refUrl) push(refUrl)
                        })
                        push(``)
                    }
                }

                // Evidence section based on engine type
            if (section.id === "dast") {
                // DAST: Request, Response, Proof
                if (evidence.requestSnippet) {
                    push(`**Request:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.requestSnippet, 2000)))
                    push("```")
                    push(``)
                }
                if (evidence.responseSnippet) {
                    push(`**Response:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.responseSnippet, 2000)))
                    push("```")
                    push(``)
                }
                if (evidence.notes) {
                    push(`**Proof:**`)
                    push(escapeMarkdownText(evidence.notes))
                    push(``)
                }
                    // DAST order matches HTML: evidence first, then other information
                    renderOtherInfo()
                } else if (section.id === "iast") {
                    // IAST order matches HTML: meta, context, flow, trace, other information
                    const iastMetaLines = []
                    if (evidence.source) iastMetaLines.push(`- Source: ${escapeMarkdownText(evidence.source)}`)
                    if (evidence.sink) iastMetaLines.push(`- Sink: ${escapeMarkdownText(evidence.sink)}`)
                    if (evidence.category) iastMetaLines.push(`- Category: ${escapeMarkdownText(evidence.category)}`)
                    if (evidence.url) iastMetaLines.push(`- URL: ${escapeMarkdownText(evidence.url)}`)
                    if (iastMetaLines.length) {
                        push(`**Meta:**`)
                        iastMetaLines.forEach(line => push(line))
                        push(``)
                    }

                    // IAST: Context/Value, Flow, Trace
                if (evidence.codeSnippet) {
                    push(`**Context / Value:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.codeSnippet, 1500)))
                    push("```")
                    push(``)
                }
                if (evidence.flow) {
                    push(`**Flow:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.flow, 2000)))
                    push("```")
                    push(``)
                } else if (evidence.notes) {
                    push(`**Flow:**`)
                    push(escapeMarkdownText(evidence.notes))
                        push(``)
                    }
                if (evidence.trace) {
                    push(`**Trace:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.trace, 2000)))
                    push("```")
                    push(``)
                }
                    if (evidence.proof) {
                        push(`**Proof:**`)
                        push(escapeMarkdownText(evidence.proof))
                        push(``)
                    }
                    renderOtherInfo()
                } else if (section.id === "sast") {
                    // SAST order matches HTML: source/sink, trace, other information
                    const source = evidence.source || null
                    const sink = evidence.sink || null
                    if (source || sink) {
                        push(`**Source / Sink:**`)
                        if (source) {
                            const loc = formatLocationRange(source.location)
                            const parts = [
                                source.name ? `Name: ${escapeMarkdownText(source.name)}` : "",
                                source.file ? `File: ${escapeMarkdownText(source.file)}` : "",
                                loc ? `Location: ${escapeMarkdownText(loc)}` : ""
                            ].filter(Boolean).join("; ")
                            if (parts) push(`- Source: ${parts}`)
                        }
                        if (sink) {
                            const loc = formatLocationRange(sink.location)
                            const parts = [
                                sink.name ? `Name: ${escapeMarkdownText(sink.name)}` : "",
                                sink.file ? `File: ${escapeMarkdownText(sink.file)}` : "",
                                loc ? `Location: ${escapeMarkdownText(loc)}` : ""
                            ].filter(Boolean).join("; ")
                            if (parts) push(`- Sink: ${parts}`)
                        }
                        push(``)
                    }

                    if (evidence.trace) {
                        const traceEntries = formatTraceEntriesForExport(evidence.trace)
                        if (traceEntries.length) {
                            push(`**Taint Trace:**`)
                            traceEntries.forEach(entry => {
                                const stage = entry.stage ? entry.stage.toUpperCase() : "STEP"
                                const details = []
                                if (entry.label) details.push(`Label: ${escapeMarkdownText(entry.label)}`)
                                if (entry.file) details.push(`File: ${escapeMarkdownText(entry.file)}`)
                                if (entry.loc) details.push(`Location: ${escapeMarkdownText(entry.loc)}`)
                                const detailHtml = details.length ? `<br>${details.join("<br>")}` : ""
                                push(`1. <small><strong>${escapeMarkdownText(stage)}</strong>${detailHtml}</small>`)
                                push(``)
                            })
                        }
                    }
                    // SAST: Source Code, Node Type
                if (evidence.codeSnippet) {
                    push(`**Source Code:**`)
                    push("```")
                    push(escapeMarkdownText(truncateSnippet(evidence.codeSnippet, 1500)))
                    push("```")
                    push(``)
                }
                    if (evidence.notes) {
                        push(`**Node Type:** ${evidence.notes}`)
                        push(``)
                    }
                    renderOtherInfo()
                } else if (section.id === "sca") {
                    renderOtherInfo()
                    // SCA: Component info
                    if (item.componentName) {
                        push(`**Component:** ${item.componentName}${item.componentVersion ? ` @ ${item.componentVersion}` : ""}`)
                        push(``)
                    }
                }

                push(`---`)
                push(``)
            })
        })

        // Methodology & Scope for technical reports too (footer)
        push(``)
        push(`Report generated using OWASP PTK scanning engines. Results depend on scan coverage and target responsiveness.`)
        const scopeText = model.meta.context?.scopeSummary && model.meta.context?.scopeSummary !== "N/A"
            ? model.meta.context.scopeSummary
            : "N/A"
        push(`**Scope:** ${escapeMarkdownText(scopeText)}`)
        push(`**Limitations:** Results depend on available routes and auth context; some flows may not be covered.`)
        push(``)
    }

    return lines.join("\n")
}

function getJsPdfCtor() {
    const root = window.jspdf
    const Ctor = root && root.jsPDF
    if (!Ctor) {
        throw new Error("jsPDF UMD not loaded: expected window.jspdf.jsPDF")
    }
    return Ctor
}

function buildPdfFromExportModel(model) {
    const JsPDF = getJsPdfCtor()
    const doc = new JsPDF({ unit: "pt", format: "a4" })
    const layout = createPdfLayout(doc, model.meta, pdfTheme)
    const margin = layout.margin
    let cursorY = layout.contentTop

    const ensureSpace = (height = 20) => {
        if (cursorY + height > layout.contentBottom) {
            doc.addPage()
            cursorY = layout.contentTop
        }
    }

    const addSectionTitle = (title) => {
        cursorY += pdfTheme.spacing.md
        ensureSpace(80)
        cursorY = layout.drawSectionTitle(title, cursorY)
        cursorY += pdfTheme.spacing.xs
    }

    const addSubsectionTitle = (title) => {
        ensureSpace(18)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.text(title, margin, cursorY)
        cursorY += pdfTheme.spacing.sm
    }

    const addAutoTable = (options) => {
        const tableDefaults = pdfTheme.tables.technical
        doc.autoTable({
            ...tableDefaults,
            ...options,
            startY: cursorY,
            margin: { left: margin, right: margin },
            styles: { ...tableDefaults.styles, ...(options.styles || {}) },
            headStyles: { ...tableDefaults.headStyles, ...(options.headStyles || {}) },
            alternateRowStyles: { ...(tableDefaults.alternateRowStyles || {}), ...(options.alternateRowStyles || {}) }
        })
        cursorY = doc.lastAutoTable.finalY + pdfTheme.spacing.lg
    }

    const drawFindingHeader = (title, severity, { confirmed = true } = {}) => {
        ensureSpace(40)
        const safeTitle = clampCellText(title, { maxChars: 90, maxLines: 1 })
        const severityKey = normalizeSeverityKey(severity || "info")
        const headerHeight = 20
        // Draw flag icon colored by severity (like reference PDF)
        drawFlagIcon(doc, { x: margin, y: cursorY, severity: severityKey, size: 14 })
        // Draw title in teal/blue color like reference PDF
        setH2(doc, pdfTheme)
        doc.setTextColor(0, 128, 128) // Teal color for title
        doc.text(safeTitle, margin + 20, cursorY + 10)
        doc.setTextColor(0)
        // Draw CONFIRMED badge on right (like reference PDF)
        const badgeX = layout.pageWidth - margin - 80
        if (confirmed) {
            drawBadge(doc, "CONFIRMED", { x: badgeX, y: cursorY - 2, fill: [46, 125, 50] })
        } else {
            drawBadge(doc, "UNCONFIRMED", { x: badgeX - 10, y: cursorY - 2, fill: [158, 158, 158], textColor: [255, 255, 255] })
        }
        cursorY += headerHeight + pdfTheme.spacing.sm
    }

    cursorY = layout.drawHeaderBlock({
        title: "OWASP PTK Security Report",
        subtitle: "Website Vulnerability Scanner Report",
        logoDataUrl: model.meta.logoDataUrl
    })
    cursorY = drawHostBanner(doc, {
        x: margin,
        y: cursorY,
        width: layout.pageWidth - margin * 2,
        text: model.meta.host || "unknown"
    })

    const tiers = (() => {
        const correlated = model.correlation || []
        let confirmed = 0
        let likely = 0
        const correlatedIds = new Set()
        correlated.forEach(group => {
            const engines = group.engines || []
            const hasDastOrIast = engines.includes("DAST") || engines.includes("IAST")
            if (hasDastOrIast) confirmed += 1
            else likely += 1
            group.instances?.forEach(instance => {
                if (instance?.findingId) correlatedIds.add(instance.findingId)
            })
        })
        const potential = model.findings.filter(item => item?.findingId && !correlatedIds.has(item.findingId)).length
        const confirmedHigh = model.findings.filter(item => {
            const sev = normalizeSeverityKey(item.severity)
            return (sev === "critical" || sev === "high") && correlatedIds.has(item.findingId)
        }).length
        return { confirmed, likely, potential, confirmedHigh }
    })()

    if (Object.keys(model.summary.byEngine || {}).length) {
        addSectionTitle("Summary")
        const riskEndY = drawRiskBarList(doc, {
            x: margin,
            y: cursorY,
            counts: model.summary.bySeverity || {},
            barMaxWidth: 180
        })
        cursorY = riskEndY + pdfTheme.spacing.sm
        const rows = buildSummaryTableRows(model)
        if (rows.length) {
            addAutoTable({
                head: [["Engine", "Critical", "High", "Medium", "Low", "Info", "Total"]],
                body: rows,
                columnStyles: { 0: { cellWidth: 70 } }
            })
        }

        const conclusion = buildExecutiveConclusion(model, tiers)
        const conclusionLines = doc.splitTextToSize(conclusion, layout.pageWidth - margin * 2)
        setBody(doc, pdfTheme)
        doc.text(conclusionLines, margin, cursorY)
        cursorY += conclusionLines.length * 12 + 6

        // Exposure & Hygiene
        ensureSpace(80)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.text("Exposure & Hygiene:", margin, cursorY)
        cursorY += 14
        doc.setFont("helvetica", "normal")
        const headerHighlights = (model.dashboard.owaspHeaders || []).slice(0, 3)
        const headersText = headerHighlights.length
            ? headerHighlights.join("; ")
            : "No header issues detected or data unavailable."
        const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
        const tokenInStorage = [...(storageDetails.localStorage || []), ...(storageDetails.sessionStorage || [])]
            .some(entry => STORAGE_TOKEN_KEY_REGEX.test(String(entry.key)))
        const cookieFlagsMissing = (model.dashboard.cookies || []).some(item => item?.httpOnly === false)
        const tokenLine = `Tokens in storage: ${tokenInStorage ? "Yes" : "No"}; Cookie HttpOnly missing: ${cookieFlagsMissing ? "Yes" : "No"}`
        const scaTopSummary = (model.sections?.sca || []).slice(0, 3).map(item => {
            const fix = item.recommendation ? truncateSnippet(item.recommendation, 80) : "Upgrade to a secure version."
            return `${item.title} (${item.severity}) - ${fix}`
        })
        const scaLineSummary = scaTopSummary.length ? scaTopSummary.join("; ") : "No high-risk dependencies identified or data unavailable."
        const exposureLines = [
            `Headers: ${headersText}`,
            `Token/storage: ${tokenLine}`,
            `Dependencies: ${scaLineSummary}`
        ]
        exposureLines.forEach(line => {
            const lines = doc.splitTextToSize(line, layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 12 + 2
        })
        cursorY += pdfTheme.spacing.xs

        // Remediation Plan
        ensureSpace(60)
        doc.setFont("helvetica", "bold")
        doc.text("Remediation Plan:", margin, cursorY)
        cursorY += 14
        doc.setFont("helvetica", "normal")
        const sevCounts = model.summary.bySeverity || {}
        addAutoTable({
            head: [["Bucket", "Items"]],
            body: [
                ["Fix now (0–7 days)", String((sevCounts.critical || 0) + (sevCounts.high || 0))],
                ["Fix soon (7–30 days)", String(sevCounts.medium || 0)],
                ["Backlog", String((sevCounts.low || 0) + (sevCounts.info || 0))]
            ],
            columnStyles: { 0: { cellWidth: 180 } }
        })
    }

    addSectionTitle("General Information")
    if (model.dashboard.technologies.length) {
        addSubsectionTitle("Technology Stack")
        const rows = model.dashboard.technologies.map(item => [item.name, item.version, item.category])
        addAutoTable({ head: [["Name", "Version", "Category"]], body: rows })
    }

    if (model.dashboard.owaspHeaders.length) {
        addSubsectionTitle("OWASP Secure Headers")
        const rows = model.dashboard.owaspHeaders.map(item => [item])
        addAutoTable({ head: [["Header"]], body: rows })
    }

    if (model.dashboard.cves.length) {
        addSubsectionTitle("CVE Lookup")
        const rows = model.dashboard.cves.map(item => [item.id, item.severity, item.evidence, item.verify])
        addAutoTable({ head: [["CVE", "Severity", "Evidence", "Verify"]], body: rows })
    }

    if (model.dashboard.headers.length) {
        addSubsectionTitle("Request Headers")
        const rows = model.dashboard.headers.map(item => [item.name, item.value])
        addAutoTable({ head: [["Header", "Value"]], body: rows })
    }

    const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
    const tokensTable = model.dashboard.tokens || []
    if (model.dashboard.cookies.length) {
        addSubsectionTitle("Cookies")
        const rows = model.dashboard.cookies.map(item => [item.domain, item.name, item.value, String(item.httpOnly)])
        addAutoTable({ head: [["Domain", "Name", "Value", "HttpOnly"]], body: rows })
    }
    if (storageDetails.localStorage.length) {
        addSubsectionTitle("Local Storage")
        const rows = storageDetails.localStorage.map(item => [item.key, truncateSnippet(item.value, 400)])
        addAutoTable({
            head: [["Key", "Value"]],
            body: rows,
            styles: { overflow: "linebreak", cellWidth: "wrap" },
            columnStyles: { 0: { cellWidth: 120 }, 1: { cellWidth: 360 } }
        })
    }
    if (storageDetails.sessionStorage.length) {
        addSubsectionTitle("Session Storage")
        const rows = storageDetails.sessionStorage.map(item => [item.key, truncateSnippet(item.value, 400)])
        addAutoTable({
            head: [["Key", "Value"]],
            body: rows,
            styles: { overflow: "linebreak", cellWidth: "wrap" },
            columnStyles: { 0: { cellWidth: 120 }, 1: { cellWidth: 360 } }
        })
    }
    if (!storageDetails.localStorage.length && !storageDetails.sessionStorage.length && model.dashboard.storage.length) {
        addSubsectionTitle("Storage")
        const rows = model.dashboard.storage.map(item => [item.type, String(item.entriesCount)])
        addAutoTable({ head: [["Storage", "Entries"]], body: rows })
    }
    if (tokensTable.length) {
        addSubsectionTitle("Tokens")
        const rows = tokensTable.map(item => [
            item.source,
            truncateSnippet(item.token, 200),
            truncateSnippet(item.payload, 400)
        ])
        addAutoTable({
            head: [["Source", "Token", "Payload"]],
            body: rows,
            styles: { overflow: "linebreak", cellWidth: "wrap" },
            columnStyles: { 0: { cellWidth: 80 }, 1: { cellWidth: 200 }, 2: { cellWidth: 200 } }
        })
        if (model.dashboard.tokenPayloadNote) {
            setBody(doc, pdfTheme)
            doc.text(model.dashboard.tokenPayloadNote, margin, cursorY)
            cursorY += pdfTheme.spacing.sm
        }
    }

    // Correlated Findings section (if any exist)
    const correlationGroups = model.correlation || buildCorrelationGroups(model.findings)
    if (correlationGroups && correlationGroups.length) {
        const correlationTitle = correlationGroups.length === 1 ? "1 correlated issue found" : "Correlated Findings"
        addSectionTitle(correlationTitle)
        const sortedCorrelation = correlationGroups.slice().sort((a, b) => {
            const sev = severityRank(a.maxSeverity) - severityRank(b.maxSeverity)
            if (sev !== 0) return sev
            const aHasRuntime = (a.engines || []).includes("DAST") || (a.engines || []).includes("IAST")
            const bHasRuntime = (b.engines || []).includes("DAST") || (b.engines || []).includes("IAST")
            if (aHasRuntime !== bHasRuntime) return aHasRuntime ? -1 : 1
            return (b.combinedConfidence || 0) - (a.combinedConfidence || 0)
        })
        sortedCorrelation.slice(0, 10).forEach(group => {
            const severityKey = normalizeSeverityKey(group.maxSeverity || "info")
            const engines = group.engines?.join(", ") || ""
            const routes = (group.sampleUrls || []).map(url => formatUrlForTable(url, "overview")).join(", ")
            const reason = buildCorrelationReason(group)

            ensureSpace(70)

            // Title (bold)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(11)
            doc.text(clampCellText(group.title, { maxChars: 100, maxLines: 1 }), margin, cursorY)
            cursorY += 14

            // Engines (muted)
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            doc.setTextColor(120, 120, 120)
            doc.text(engines, margin, cursorY)
            doc.setTextColor(0)
            cursorY += 12

            // Severity badge + Confidence + Assets
            const sevColor = pdfTheme.severityColors[severityKey] || pdfTheme.severityColors.info
            const badgeY = cursorY
            const badgeWidth = drawBadge(doc, severityKey.toUpperCase(), { x: margin, y: badgeY, fill: sevColor })
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            const metaX = margin + badgeWidth + 10
            doc.text(`Confidence: ${Math.round(group.combinedConfidence || 0)}   Assets: ${group.affectedAssetsCount || 0}`, metaX, badgeY + 12)
            cursorY += 28

            // Impacted routes
            if (routes) {
                doc.setTextColor(80, 80, 80)
                const routesText = `Impacted routes: ${routes}`
                const routesLines = doc.splitTextToSize(routesText, layout.pageWidth - margin * 2)
                doc.text(routesLines, margin, cursorY)
                cursorY += routesLines.length * 11 + 6
            }

            // Why high confidence
            if (reason) {
                doc.setTextColor(80, 80, 80)
                doc.text(`Why high confidence: ${reason}`, margin, cursorY)
                cursorY += 14
            }

            doc.setTextColor(0)
            cursorY += pdfTheme.spacing.sm

            // Draw a light separator line
            doc.setDrawColor(230, 230, 230)
            doc.setLineWidth(0.5)
            doc.line(margin, cursorY, layout.pageWidth - margin, cursorY)
            cursorY += pdfTheme.spacing.sm
        })
    }

    const sortBySeverity = (a, b) => severityRank(a?.severity) - severityRank(b?.severity)
    const sections = [
        { id: "dast", label: "DAST" },
        { id: "iast", label: "IAST" },
        { id: "sast", label: "SAST" },
        { id: "sca", label: "SCA" }
    ]

    // Helper to render a code block in PDF
    const drawCodeBlock = (label, content) => {
        if (!content) return
        const text = truncateSnippet(content, 2000)
        const codeLines = doc.splitTextToSize(text, layout.pageWidth - margin * 2)
        const lineHeight = 9

        let remaining = codeLines.slice()

        while (remaining.length) {
            ensureSpace(60)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(9)
            doc.setTextColor(0, 0, 0)
            const title = `${label}:`
            doc.text(title, margin, cursorY)
            cursorY += 12

            doc.setFont("courier", "normal")
            doc.setFontSize(8)
            doc.setTextColor(60, 60, 60)

            const availableHeight = layout.contentBottom - cursorY
            const maxLines = Math.max(1, Math.floor(availableHeight / lineHeight) - 1)
            const slice = remaining.slice(0, maxLines)
            doc.text(slice, margin, cursorY)
            cursorY += slice.length * lineHeight + 6
            remaining = remaining.slice(maxLines)

            doc.setTextColor(0)
            if (remaining.length) {
                doc.addPage()
                cursorY = layout.contentTop
            }
        }
    }

    const drawOtherInformationBlock = (item, sectionId) => {
        const description = item.description ? stripHtmlToText(item.description) : ""
        const fix = item.recommendation ? stripHtmlToText(item.recommendation) : ""
        const owaspLabel = (item.owasp || [])
            .map(entry => (typeof entry === "string" ? entry : entry?.name || entry?.id || ""))
            .filter(Boolean)
            .join(", ")
        const refsList = (item.references || [])
            .map(ref => ref?.url || ref)
            .filter(Boolean)
            .slice(0, 5)

        const hasContent = (description && sectionId !== "sca")
            || fix
            || (item.cwe?.length)
            || owaspLabel
            || refsList.length
        if (!hasContent) return

        const renderLabelValue = (label, value) => {
            if (!value) return
            ensureSpace(30)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(9)
            doc.text(`${label}:`, margin, cursorY)
            cursorY += 12
            doc.setFont("helvetica", "normal")
            doc.setTextColor(80, 80, 80)
            const lines = doc.splitTextToSize(String(value), layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 10 + 6
            doc.setTextColor(0)
        }

        if (description && sectionId !== "sca") {
            renderLabelValue("Description", truncateSnippet(description, 1200))
        }
        if (fix) {
            renderLabelValue("Recommendation", truncateSnippet(fix, 800))
        }
        if (item.cwe?.length) {
            renderLabelValue("CWE", item.cwe.join(", "))
        }
        if (owaspLabel) {
            renderLabelValue("OWASP", owaspLabel)
        }
        if (refsList.length) {
            renderLabelValue("References", refsList.join("\n"))
        }
    }

    const drawIastMetaBlock = (evidence) => {
        const lines = []
        if (evidence?.source) lines.push(`- Source: ${evidence.source}`)
        if (evidence?.sink) lines.push(`- Sink: ${evidence.sink}`)
        if (evidence?.category) lines.push(`- Category: ${evidence.category}`)
        if (evidence?.url) lines.push(`- URL: ${evidence.url}`)
        if (!lines.length) return

        ensureSpace(40)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.setFontSize(9)
        doc.text("Meta:", margin, cursorY)
        cursorY += 12
        doc.setFont("helvetica", "normal")
        doc.setTextColor(80, 80, 80)
        lines.forEach(line => {
            const wrapped = doc.splitTextToSize(line, layout.pageWidth - margin * 2)
            doc.text(wrapped, margin, cursorY)
            cursorY += wrapped.length * 10 + 2
        })
        doc.setTextColor(0)
        cursorY += 6
    }

    const drawSastSourceSinkBlock = (evidence) => {
        const source = evidence?.source || null
        const sink = evidence?.sink || null
        if (!source && !sink) return

        ensureSpace(40)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.setFontSize(9)
        doc.text("Source / Sink:", margin, cursorY)
        cursorY += 12
        doc.setFont("helvetica", "normal")
        doc.setTextColor(80, 80, 80)
        const buildLine = (label, endpoint) => {
            if (!endpoint) return ""
            const locText = formatLocationRange(endpoint.location)
            const parts = [
                endpoint.name ? `Name: ${endpoint.name}` : "",
                endpoint.file ? `File: ${endpoint.file}` : "",
                locText ? `Location: ${locText}` : ""
            ].filter(Boolean).join("; ")
            return parts ? `${label}: ${parts}` : ""
        }
        const sourceLine = buildLine("Source", source)
        const sinkLine = buildLine("Sink", sink)
        if (sourceLine) {
            const wrapped = doc.splitTextToSize(sourceLine, layout.pageWidth - margin * 2)
            doc.text(wrapped, margin, cursorY)
            cursorY += wrapped.length * 10 + 2
        }
        if (sinkLine) {
            const wrapped = doc.splitTextToSize(sinkLine, layout.pageWidth - margin * 2)
            doc.text(wrapped, margin, cursorY)
            cursorY += wrapped.length * 10 + 2
        }
        doc.setTextColor(0)
        cursorY += 6
    }

    const drawTraceListBlock = (label, trace) => {
        const entries = formatTraceEntriesForExport(trace)
        if (!entries.length) return
        ensureSpace(40)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.setFontSize(9)
        doc.text(`${label}:`, margin, cursorY)
        cursorY += 12
        doc.setFont("helvetica", "normal")
        doc.setTextColor(80, 80, 80)
        entries.forEach(entry => {
            const stage = entry.stage ? String(entry.stage).toUpperCase() : "STEP"
            const header = `• ${stage}`
            const headerLines = doc.splitTextToSize(header, layout.pageWidth - margin * 2)
            doc.text(headerLines, margin, cursorY)
            cursorY += headerLines.length * 10 + 2

            const detailLines = []
            if (entry.label) detailLines.push(`Label: ${entry.label}`)
            if (entry.file) detailLines.push(`File: ${entry.file}`)
            if (entry.loc) detailLines.push(`Location: ${entry.loc}`)
            detailLines.forEach(detail => {
                const wrapped = doc.splitTextToSize(detail, layout.pageWidth - margin * 2)
                doc.text(wrapped, margin + 12, cursorY)
                cursorY += wrapped.length * 10 + 2
            })
            cursorY += 2
        })
        doc.setTextColor(0)
        cursorY += 6
    }

    const drawExecMappingBlock = (item) => {
        const cweList = Array.isArray(item?.cwe) ? item.cwe : (item?.cwe ? [item.cwe] : [])
        const owaspList = resolveOwaspList(item)
        const refsList = (item?.references || []).map(ref => ref?.url || ref).filter(Boolean).slice(0, 5)
        if (!cweList.length && !owaspList.length && !refsList.length) return

        const renderLabelValue = (label, value) => {
            if (!value) return
            ensureSpace(30)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(9)
            doc.text(`${label}:`, margin, cursorY)
            cursorY += 12
            doc.setFont("helvetica", "normal")
            doc.setTextColor(80, 80, 80)
            const lines = doc.splitTextToSize(String(value), layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 10 + 6
            doc.setTextColor(0)
        }

        if (cweList.length) {
            renderLabelValue("CWE", cweList.join(", "))
        }
        if (owaspList.length) {
            renderLabelValue("OWASP", owaspList.join(", "))
        }
        if (refsList.length) {
            renderLabelValue("References", refsList.join("\n"))
        }
    }

    sections.forEach(section => {
        const findings = (model.sections?.[section.id] || []).slice().sort(sortBySeverity)
        if (!findings.length) return
        addSectionTitle(section.label)

        // Render each finding as a card-like block (similar to executive report)
        findings.forEach(item => {
            const severityKey = normalizeSeverityKey(item.severity)
            const locationText = formatAssetForDetail(item.location)

            ensureSpace(120)

            // Finding ID and Title (bold)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(10)
            const titleText = clampCellText(`${item.findingId || section.label} - ${item.title}`, { maxChars: 100, maxLines: 1 })
            doc.text(titleText, margin, cursorY)
            cursorY += 14

            // Location (muted)
            if (locationText) {
                doc.setFont("helvetica", "normal")
                doc.setFontSize(9)
                doc.setTextColor(120, 120, 120)
                const locLines = doc.splitTextToSize(locationText, layout.pageWidth - margin * 2)
                doc.text(locLines.slice(0, 2), margin, cursorY)
                cursorY += locLines.slice(0, 2).length * 11
                doc.setTextColor(0)
            }

            // Severity badge + Confidence
            const sevColor = pdfTheme.severityColors[severityKey] || pdfTheme.severityColors.info
            const badgeY = cursorY
            const badgeWidth = drawBadge(doc, severityKey.toUpperCase(), { x: margin, y: badgeY, fill: sevColor })
            if (item.confidence != null) {
                doc.setFont("helvetica", "normal")
                doc.setFontSize(9)
                doc.text(`Confidence: ${Math.round(item.confidence)}`, margin + badgeWidth + 10, badgeY + 12)
            }
            cursorY += 28

            // Evidence section based on engine type
            const evidence = item.evidence || {}
            if (section.id === "dast") {
                // DAST: Request, Response, Proof
                if (evidence.requestSnippet) {
                    drawCodeBlock("Request", evidence.requestSnippet)
                }
                if (evidence.responseSnippet) {
                    drawCodeBlock("Response", evidence.responseSnippet)
                    cursorY += pdfTheme.spacing.sm
                }
                if (evidence.notes) {
                    drawCodeBlock("Proof", evidence.notes)
                    cursorY += pdfTheme.spacing.sm
                }
                // DAST order matches HTML: evidence first, then other information
                drawOtherInformationBlock(item, section.id)
            } else if (section.id === "iast") {
                // IAST order matches HTML: meta, context, flow, trace, other information
                drawIastMetaBlock(evidence)
                if (evidence.codeSnippet) {
                    drawCodeBlock("Context / Value", evidence.codeSnippet)
                }
                if (evidence.flow) {
                    drawCodeBlock("Flow", evidence.flow)
                } else if (evidence.notes) {
                    ensureSpace(30)
                    setBody(doc, pdfTheme)
                    doc.setFont("helvetica", "bold")
                    doc.setFontSize(9)
                    doc.text("Flow:", margin, cursorY)
                    cursorY += 12
                    doc.setFont("helvetica", "normal")
                    doc.setTextColor(80, 80, 80)
                    const notesLines = doc.splitTextToSize(evidence.notes, layout.pageWidth - margin * 2)
                    doc.text(notesLines.slice(0, 4), margin, cursorY)
                    cursorY += notesLines.slice(0, 4).length * 10 + 8
                    doc.setTextColor(0)
                }
                if (evidence.trace) {
                    drawCodeBlock("Trace", evidence.trace)
                }
                if (evidence.proof) {
                    drawCodeBlock("Proof", evidence.proof)
                }
                drawOtherInformationBlock(item, section.id)
            } else if (section.id === "sast") {
                // SAST order matches HTML: source/sink, trace, other information
                drawSastSourceSinkBlock(evidence)
                if (evidence.trace) {
                    drawTraceListBlock("Taint Trace", evidence.trace)
                }
                if (evidence.codeSnippet) {
                    drawCodeBlock("Source Code", evidence.codeSnippet)
                }
                if (evidence.notes) {
                    ensureSpace(30)
                    setBody(doc, pdfTheme)
                    doc.setFont("helvetica", "bold")
                    doc.setFontSize(9)
                    doc.text("Node Type:", margin, cursorY)
                    cursorY += 12
                    doc.setFont("helvetica", "normal")
                    doc.setTextColor(80, 80, 80)
                    doc.text(evidence.notes, margin, cursorY)
                    cursorY += 12
                    doc.setTextColor(0)
                }
                drawOtherInformationBlock(item, section.id)
            } else if (section.id === "sca") {
                drawOtherInformationBlock(item, section.id)
                // SCA: Component info
                if (item.componentName) {
                    ensureSpace(30)
                    setBody(doc, pdfTheme)
                    doc.setFont("helvetica", "bold")
                    doc.setFontSize(9)
                    doc.text("Component:", margin, cursorY)
                    cursorY += 12
                    doc.setFont("helvetica", "normal")
                    doc.setTextColor(80, 80, 80)
                    doc.text(`${item.componentName}${item.componentVersion ? ` @ ${item.componentVersion}` : ""}`, margin, cursorY)
                    cursorY += 12
                    doc.setTextColor(0)
                }
            }

            cursorY += pdfTheme.spacing.sm

            // Draw a light separator line
            doc.setDrawColor(230, 230, 230)
            doc.setLineWidth(0.5)
            doc.line(margin, cursorY, layout.pageWidth - margin, cursorY)
            cursorY += pdfTheme.spacing.md
        })
    })

    cursorY += pdfTheme.spacing.lg
    ensureSpace(80)
    const methodologyText = "Report generated using OWASP PTK scanning engines. Results depend on scan coverage and target responsiveness."
    const scopeText = model.meta.context?.scopeSummary && model.meta.context?.scopeSummary !== "N/A"
        ? `Scope: ${model.meta.context.scopeSummary}`
        : "Scope: N/A"
    const limitationsText = "Limitations: Results depend on available routes and auth context; some flows may not be covered."
    const methodologyLines = doc.splitTextToSize(`${methodologyText}\n\n${scopeText}\n${limitationsText}`, layout.pageWidth - margin * 2)
    setBody(doc, pdfTheme)
    doc.text(methodologyLines, margin, cursorY)
    cursorY += methodologyLines.length * 12

    const totalPages = doc.internal.getNumberOfPages()
    for (let page = 1; page <= totalPages; page += 1) {
        doc.setPage(page)
        layout.drawHeader(page, totalPages)
        layout.drawFooter(page, totalPages)
    }

    return doc
}

function buildExecutivePdfFromReportModel(model) {
    const JsPDF = getJsPdfCtor()
    const doc = new JsPDF({ unit: "pt", format: "a4" })
    const layout = createPdfLayout(doc, model.meta, pdfTheme)
    const margin = layout.margin
    let cursorY = layout.contentTop

    const ensureSpace = (height = 20) => {
        if (cursorY + height > layout.contentBottom) {
            doc.addPage()
            cursorY = layout.contentTop
        }
    }

    const addSectionTitle = (title) => {
        cursorY += pdfTheme.spacing.md
        ensureSpace(24)
        cursorY = layout.drawSectionTitle(title, cursorY)
        cursorY += pdfTheme.spacing.xs
    }

    const addAutoTable = (options) => {
        const tableDefaults = pdfTheme.tables.executive
        doc.autoTable({
            ...tableDefaults,
            ...options,
            startY: cursorY,
            margin: { left: margin, right: margin },
            styles: { ...tableDefaults.styles, ...(options.styles || {}) },
            headStyles: { ...tableDefaults.headStyles, ...(options.headStyles || {}) },
            alternateRowStyles: { ...(tableDefaults.alternateRowStyles || {}), ...(options.alternateRowStyles || {}) }
        })
        cursorY = doc.lastAutoTable.finalY + pdfTheme.spacing.lg
    }

    const drawExecMappingBlock = (item) => {
        const cweList = Array.isArray(item?.cwe) ? item.cwe : (item?.cwe ? [item.cwe] : [])
        const owaspList = resolveOwaspList(item)
        const refsList = (item?.references || []).map(ref => ref?.url || ref).filter(Boolean).slice(0, 5)
        if (!cweList.length && !owaspList.length && !refsList.length) return

        const renderLabelValue = (label, value) => {
            if (!value) return
            ensureSpace(30)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(9)
            doc.text(`${label}:`, margin, cursorY)
            cursorY += 12
            doc.setFont("helvetica", "normal")
            doc.setTextColor(80, 80, 80)
            const lines = doc.splitTextToSize(String(value), layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 10 + 6
            doc.setTextColor(0)
        }

        if (cweList.length) {
            renderLabelValue("CWE", cweList.join(", "))
        }
        if (owaspList.length) {
            renderLabelValue("OWASP", owaspList.join(", "))
        }
        if (refsList.length) {
            renderLabelValue("References", refsList.join("\n"))
        }
    }

    cursorY = layout.drawHeaderBlock({
        title: "OWASP PTK Security Report",
        subtitle: "Website Vulnerability Scanner Report",
        logoDataUrl: model.meta.logoDataUrl
    })
    cursorY = drawHostBanner(doc, {
        x: margin,
        y: cursorY,
        width: layout.pageWidth - margin * 2,
        text: model.meta.host || "unknown"
    })

    if (Object.keys(model.summary.byEngine || {}).length) {
        const tiers = (() => {
            const correlated = model.correlation || []
            let confirmed = 0
            let likely = 0
            const correlatedIds = new Set()
            correlated.forEach(group => {
                const engines = group.engines || []
                const hasDastOrIast = engines.includes("DAST") || engines.includes("IAST")
                if (hasDastOrIast) confirmed += 1
                else likely += 1
                group.instances?.forEach(instance => {
                    if (instance?.findingId) correlatedIds.add(instance.findingId)
                })
            })
            const potential = model.findings.filter(item => item?.findingId && !correlatedIds.has(item.findingId)).length
            const confirmedHigh = model.findings.filter(item => {
                const sev = normalizeSeverityKey(item.severity)
                return (sev === "critical" || sev === "high") && correlatedIds.has(item.findingId)
            }).length
            return { confirmed, likely, potential, confirmedHigh }
        })()

        addSectionTitle("Summary")
        const riskEndY = drawRiskBarList(doc, {
            x: margin,
            y: cursorY,
            counts: model.summary.bySeverity || {},
            barMaxWidth: 180
        })
        cursorY = riskEndY + pdfTheme.spacing.sm
        const summaryRows = buildSummaryTableRows(model)
        if (summaryRows.length) {
            addAutoTable({
                head: [["Engine", "Critical", "High", "Medium", "Low", "Info", "Total"]],
                body: summaryRows,
                columnStyles: { 0: { cellWidth: 70 } }
            })
        }

        const conclusion = buildExecutiveConclusion(model, tiers)
        const conclusionLines = doc.splitTextToSize(conclusion, layout.pageWidth - margin * 2)
        setBody(doc, pdfTheme)
        doc.text(conclusionLines, margin, cursorY)
        cursorY += conclusionLines.length * 12 + 6

        // Exposure & Hygiene in Summary
        ensureSpace(80)
        setBody(doc, pdfTheme)
        doc.setFont("helvetica", "bold")
        doc.text("Exposure & Hygiene:", margin, cursorY)
        cursorY += 14
        doc.setFont("helvetica", "normal")
        const headerHighlights = (model.dashboard.owaspHeaders || []).slice(0, 3)
        const headersText = headerHighlights.length
            ? headerHighlights.join("; ")
            : "No header issues detected or data unavailable."
        const storageDetails = model.dashboard.storageDetails || { localStorage: [], sessionStorage: [] }
        const tokenInStorage = [...(storageDetails.localStorage || []), ...(storageDetails.sessionStorage || [])]
            .some(entry => STORAGE_TOKEN_KEY_REGEX.test(String(entry.key)))
        const cookieFlagsMissing = (model.dashboard.cookies || []).some(item => item?.httpOnly === false)
        const tokenLine = `Tokens in storage: ${tokenInStorage ? "Yes" : "No"}; Cookie HttpOnly missing: ${cookieFlagsMissing ? "Yes" : "No"}`
        const scaTopSummary = (model.sections?.sca || []).slice(0, 3).map(item => {
            const fix = item.recommendation ? truncateSnippet(item.recommendation, 80) : "Upgrade to a secure version."
            return `${item.title} (${item.severity}) - ${fix}`
        })
        const scaLineSummary = scaTopSummary.length ? scaTopSummary.join("; ") : "No high-risk dependencies identified or data unavailable."
        const exposureLines = [
            `Headers: ${headersText}`,
            `Token/storage: ${tokenLine}`,
            `Dependencies: ${scaLineSummary}`
        ]
        exposureLines.forEach(line => {
            const lines = doc.splitTextToSize(line, layout.pageWidth - margin * 2)
            doc.text(lines, margin, cursorY)
            cursorY += lines.length * 12 + 2
        })
        cursorY += pdfTheme.spacing.xs

        // Remediation Plan in Summary
        ensureSpace(60)
        doc.setFont("helvetica", "bold")
        doc.text("Remediation Plan:", margin, cursorY)
        cursorY += 14
        doc.setFont("helvetica", "normal")
        const sevCounts = model.summary.bySeverity || {}
        addAutoTable({
            head: [["Bucket", "Items"]],
            body: [
                ["Fix now (0–7 days)", String((sevCounts.critical || 0) + (sevCounts.high || 0))],
                ["Fix soon (7–30 days)", String(sevCounts.medium || 0)],
                ["Backlog", String((sevCounts.low || 0) + (sevCounts.info || 0))]
            ],
            columnStyles: { 0: { cellWidth: 180 } }
        })
    }

    const severityCounts = model.summary.bySeverity || {}
    const topLabel = buildTopRisksLabel(severityCounts)
    const topPool = severityCounts.critical > 0
        ? model.findings.filter(item => normalizeSeverityKey(item?.severity) === "critical")
        : model.findings
    const topGrouped = groupFindingsForExec(topPool, {
        keyFn: item => item.title || item.findingId || "finding",
        maxItems: 5
    })

    if (topGrouped.length) {
        addSectionTitle(topLabel)
        // Render each finding as a card-like block (matching HTML layout)
        topGrouped.forEach(entry => {
            const item = entry.item
            const occ = entry.count > 1 ? ` (${entry.count} occurrences)` : ""
            const owner = inferOwnerHint(item)
            const asset = formatAssetForOverview(item.location)
            const severityKey = normalizeSeverityKey(item.severity)

            ensureSpace(80)

            // Title (bold)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(11)
            const titleText = clampCellText(`${item.title}${occ}`, { maxChars: 100, maxLines: 1 })
            doc.text(titleText, margin, cursorY)
            cursorY += 14

            // Engine • Asset (muted)
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            doc.setTextColor(120, 120, 120)
            doc.text(`${item.engine || "DAST"} • ${asset}`, margin, cursorY)
            doc.setTextColor(0)
            cursorY += 12

            // Severity badge + Owner
            const sevColor = pdfTheme.severityColors[severityKey] || pdfTheme.severityColors.info
            const badgeY = cursorY
            const badgeWidth = drawBadge(doc, severityKey.toUpperCase(), { x: margin, y: badgeY, fill: sevColor })
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            const ownerX = margin + badgeWidth + 10
            doc.text(`Owner: ${owner}`, ownerX, badgeY + 12)
            cursorY += 28

            // CWE/OWASP mapping
            drawExecMappingBlock(item)
            doc.setTextColor(0)
            cursorY += pdfTheme.spacing.sm

            // Draw a light separator line
            doc.setDrawColor(230, 230, 230)
            doc.setLineWidth(0.5)
            doc.line(margin, cursorY, layout.pageWidth - margin, cursorY)
            cursorY += pdfTheme.spacing.sm
        })
    }

    if (model.correlation && model.correlation.length) {
        const correlationTitle = model.correlation.length === 1 ? "1 correlated issue found" : "Correlated Findings"
        addSectionTitle(correlationTitle)
        const sorted = model.correlation.slice().sort((a, b) => {
            const sev = severityRank(a.maxSeverity) - severityRank(b.maxSeverity)
            if (sev !== 0) return sev
            const aHasRuntime = (a.engines || []).includes("DAST") || (a.engines || []).includes("IAST")
            const bHasRuntime = (b.engines || []).includes("DAST") || (b.engines || []).includes("IAST")
            if (aHasRuntime !== bHasRuntime) return aHasRuntime ? -1 : 1
            return (b.combinedConfidence || 0) - (a.combinedConfidence || 0)
        })
        // Render each correlated finding as a card-like block (matching HTML layout)
        sorted.slice(0, 10).forEach(group => {
            const severityKey = normalizeSeverityKey(group.maxSeverity || "info")
            const engines = group.engines?.join(", ") || ""
            const routes = (group.sampleUrls || []).map(url => formatUrlForTable(url, "overview")).join(", ")
            const reason = buildCorrelationReason(group)

            ensureSpace(70)

            // Title (bold)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(11)
            doc.text(clampCellText(group.title, { maxChars: 100, maxLines: 1 }), margin, cursorY)
            cursorY += 14

            // Engines (muted)
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            doc.setTextColor(120, 120, 120)
            doc.text(engines, margin, cursorY)
            doc.setTextColor(0)
            cursorY += 12

            // Severity badge + Confidence + Assets
            const sevColor = pdfTheme.severityColors[severityKey] || pdfTheme.severityColors.info
            const badgeY = cursorY
            const badgeWidth = drawBadge(doc, severityKey.toUpperCase(), { x: margin, y: badgeY, fill: sevColor })
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            const metaX = margin + badgeWidth + 10
            doc.text(`Confidence: ${Math.round(group.combinedConfidence || 0)}   Assets: ${group.affectedAssetsCount || 0}`, metaX, badgeY + 12)
            cursorY += 28

            // Impacted routes
            if (routes) {
                doc.setTextColor(80, 80, 80)
                const routesText = `Impacted routes: ${routes}`
                const routesLines = doc.splitTextToSize(routesText, layout.pageWidth - margin * 2)
                doc.text(routesLines, margin, cursorY)
                cursorY += routesLines.length * 11 + 6
            }

            // Why high confidence
            if (reason) {
                doc.setTextColor(80, 80, 80)
                doc.text(`Why high confidence: ${reason}`, margin, cursorY)
                cursorY += 14
            }

            doc.setTextColor(0)
            cursorY += pdfTheme.spacing.sm

            // Draw a light separator line
            doc.setDrawColor(230, 230, 230)
            doc.setLineWidth(0.5)
            doc.line(margin, cursorY, layout.pageWidth - margin, cursorY)
            cursorY += pdfTheme.spacing.sm
        })
    }

    // Engine sections (DAST, IAST, SAST, SCA) - card-like blocks matching HTML
    const engineSections = [
        { id: "dast", label: "DAST" },
        { id: "iast", label: "IAST" },
        { id: "sast", label: "SAST" },
        { id: "sca", label: "SCA" }
    ]
    engineSections.forEach(section => {
        const findings = model.sections?.[section.id] || []
        if (!findings.length) return
        const grouped = groupFindingsForExec(findings, {
            keyFn: section.id === "sca"
                ? normalizeScaKey
                : (item) => item.title || item.findingId || "finding"
        })
        addSectionTitle(`${section.label} Top Findings`)

        // Render each finding as a card-like block
        grouped.forEach(entry => {
            const item = entry.item
            const occ = entry.count > 1 ? ` - ${entry.count} occurrences` : ""
            const asset = formatAssetForOverview(item.location)
            const severityKey = normalizeSeverityKey(item.severity)
            const description = item.description ? stripHtmlToText(item.description) : ""
            const fix = item.recommendation ? stripHtmlToText(item.recommendation) : inferFix(item)

            ensureSpace(150)

            // Title (bold)
            setBody(doc, pdfTheme)
            doc.setFont("helvetica", "bold")
            doc.setFontSize(11)
            const titleText = clampCellText(`${item.title}${occ}`, { maxChars: 100, maxLines: 1 })
            doc.text(titleText, margin, cursorY)
            cursorY += 14

            // Asset (muted)
            doc.setFont("helvetica", "normal")
            doc.setFontSize(9)
            doc.setTextColor(120, 120, 120)
            doc.text(asset, margin, cursorY)
            doc.setTextColor(0)
            cursorY += 14

            // Severity badge
            const sevColor = pdfTheme.severityColors[severityKey] || pdfTheme.severityColors.info
            drawBadge(doc, severityKey.toUpperCase(), { x: margin, y: cursorY - 4, fill: sevColor })
            cursorY += 24

            // Description (for DAST/IAST/SAST, not SCA)
            if (description && section.id !== "sca") {
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("Description:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                const descLines = doc.splitTextToSize(description, layout.pageWidth - margin * 2)
                doc.text(descLines, margin, cursorY)
                cursorY += descLines.length * 11 + 10
            }

            // Fix/Recommendation
            if (fix) {
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("Recommendation:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                const recLines = doc.splitTextToSize(fix, layout.pageWidth - margin * 2)
                doc.text(recLines, margin, cursorY)
                cursorY += recLines.length * 11 + 10
            }

            // CWE (separate from OWASP)
            const cweList = Array.isArray(item.cwe) ? item.cwe : (item.cwe ? [item.cwe] : [])
            if (cweList.length) {
                ensureSpace(40)
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("CWE:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                const cweText = cweList.join(", ")
                const cweLines = doc.splitTextToSize(cweText, layout.pageWidth - margin * 2)
                doc.text(cweLines, margin, cursorY)
                cursorY += cweLines.length * 11 + 10
            }

            // OWASP (separate from CWE)
            const owaspList = resolveOwaspList(item)
            if (owaspList.length) {
                ensureSpace(40)
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("OWASP:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                const owaspText = owaspList.join(", ")
                const owaspLines = doc.splitTextToSize(owaspText, layout.pageWidth - margin * 2)
                doc.text(owaspLines, margin, cursorY)
                cursorY += owaspLines.length * 11 + 10
            }

            // References (each on separate line)
            const refsList = (item.references || []).map(ref => ref?.url || ref).filter(Boolean)
            if (refsList.length) {
                ensureSpace(50)
                setBody(doc, pdfTheme)
                doc.setFont("helvetica", "bold")
                doc.setTextColor(0, 0, 0)
                doc.text("References:", margin, cursorY)
                cursorY += 14
                doc.setFont("helvetica", "normal")
                doc.setTextColor(80, 80, 80)
                refsList.forEach(refUrl => {
                    ensureSpace(20)
                    const refLines = doc.splitTextToSize(refUrl, layout.pageWidth - margin * 2)
                    doc.text(refLines, margin, cursorY)
                    cursorY += refLines.length * 11 + 2
                })
                cursorY += 6
            }

            doc.setTextColor(0)
            cursorY += pdfTheme.spacing.md

            // Draw a light separator line
            doc.setDrawColor(220, 220, 220)
            doc.setLineWidth(0.5)
            doc.line(margin, cursorY, layout.pageWidth - margin, cursorY)
            cursorY += pdfTheme.spacing.md
        })
    })

    cursorY += pdfTheme.spacing.lg
    ensureSpace(80)
    const methodologyText = "Report generated using OWASP PTK scanning engines. Executive preset includes top findings only and excludes sensitive evidence by default. Results depend on scan coverage and target responsiveness."
    const scopeText = model.meta.context?.scopeSummary && model.meta.context?.scopeSummary !== "N/A"
        ? `Scope: ${model.meta.context.scopeSummary}`
        : "Scope: N/A"
    const limitationsText = "Limitations: Results depend on available routes and auth context; some flows may not be covered."
    const methodologyLines = doc.splitTextToSize(`${methodologyText}\n\n${scopeText}\n${limitationsText}`, layout.pageWidth - margin * 2)
    setBody(doc, pdfTheme)
    doc.text(methodologyLines, margin, cursorY)
    cursorY += methodologyLines.length * 12

    const totalPages = doc.internal.getNumberOfPages()
    for (let page = 1; page <= totalPages; page += 1) {
        doc.setPage(page)
        layout.drawHeader(page, totalPages)
        layout.drawFooter(page, totalPages)
    }

    return doc
}

function sanitizeFilename(value) {
    if (!value) return "report"
    return String(value).replace(/[^a-zA-Z0-9._-]/g, "_")
}

function setExportStatus(message, { error = false } = {}) {
    const $status = $("#export_status")
    if (!message) {
        $status.hide().text("")
        return
    }
    $status.text(message)
    $status.toggleClass("red", !!error)
    $status.toggleClass("grey", !error)
    $status.show()
}

function exportMarkdown(options = {}) {
    try {
        exportModel.meta.generatedAt = exportModel.meta.generatedAt || new Date().toISOString()
        const filteredModel = getFilteredExportModel()
        filteredModel.meta.generatedAt = exportModel.meta.generatedAt
        const reportModel = buildReportModel(filteredModel, options)
        const content = buildMarkdownFromExportModel(reportModel)
        const filename = `PTK_Report_${sanitizeFilename(exportModel.meta.host)}_${new Date().toISOString().replace(/[:]/g, "-")}.md`
        const blob = new Blob([content], { type: "text/markdown" })
        const link = document.createElement("a")
        link.download = filename
        link.href = window.URL.createObjectURL(blob)
        link.click()
        setExportStatus("")
    } catch (err) {
        setExportStatus(err?.message || "Markdown export failed", { error: true })
    }
}

function exportPdfReport(scanEnvelopeOrProject, options = {}) {
    exportModel.meta.generatedAt = exportModel.meta.generatedAt || new Date().toISOString()
    const filteredModel = getFilteredExportModel()
    filteredModel.meta.generatedAt = exportModel.meta.generatedAt
    const reportModel = buildReportModel(filteredModel, options)
    if ((options.preset || "executive") === "technical") {
        return buildPdfFromExportModel(reportModel)
    }
    return buildExecutivePdfFromReportModel(reportModel)
}

async function exportPdf() {
    try {
        document.body.classList.add("ptk-exporting")
        setExportStatus("Exporting PDF...")
        const preset = $('#report_preset').val() || "executive"
        const includeSensitiveEvidence = $('#pdf_include_sensitive').is(':checked')
        const logoDataUrl = await loadReportLogoDataUrl()
        const doc = exportPdfReport(null, { preset, includeSensitiveEvidence, logoDataUrl })
        const filename = `PTK_Report_${sanitizeFilename(exportModel.meta.host)}_${new Date().toISOString().replace(/[:]/g, "-")}.pdf`
        doc.save(filename)
        setExportStatus("")
    } catch (err) {
        setExportStatus(err?.message || "PDF export failed", { error: true })
    } finally {
        document.body.classList.remove("ptk-exporting")
    }
}


function exportSelected(format) {
    if ($('#export_pdf_btn').hasClass('disabled') || $('#export_md_btn').hasClass('disabled')) return
    const preset = $('#report_preset').val() || "executive"
    const includeSensitiveEvidence = $('#pdf_include_sensitive').is(':checked')
    if (format === "markdown") {
        exportMarkdown({ preset, includeSensitiveEvidence })
        return
    }
    exportPdf()
}

function sanitizeRichText(html) {
    if (!html) return ""
    return dompurify.sanitize(html, { ALLOWED_TAGS: SAST_ALLOWED_TAGS, ALLOWED_ATTR: SAST_ALLOWED_ATTRS })
}

function escapeText(value, fallback = "-") {
    if (value === undefined || value === null || value === "") return fallback
    return ptk_utils.escapeHtml(String(value))
}

function resolveConfidenceValue(...candidates) {
    for (const value of candidates) {
        if (value === undefined || value === null || value === "") continue
        const num = Number(value)
        if (Number.isFinite(num)) {
            return Math.max(0, Math.min(100, num))
        }
    }
    return null
}

function formatConfidence(confidence) {
    if (!Number.isFinite(confidence)) return null
    return Math.round(confidence)
}

function renderConfidenceLine(confidence) {
    const value = formatConfidence(confidence)
    if (value === null) return ""
    return `<p><b>Confidence:</b> ${value}</p>`
}

function getSeverityMeta(severity) {
    const normalized = String(severity || "").toLowerCase()
    const defaults = REPORT_SEVERITY_STYLES[normalized] || {
        color: "grey",
        icon: "info circle",
        label: severity ? severity : "Info"
    }
    return {
        color: defaults.color,
        icon: `<i class="${defaults.icon} ${defaults.color} icon"></i>`,
        label: defaults.label
    }
}

function normalizeSeverityKey(value) {
    const normalized = String(value || "").toLowerCase()
    if (UI_SEVERITY_ORDER.includes(normalized)) return normalized
    return "info"
}

const SEVERITY_RANKING = ["critical", "high", "medium", "low", "info"]
function severityRank(severity) {
    const normalized = String(severity || "").toLowerCase()
    const index = SEVERITY_RANKING.indexOf(normalized)
    return index === -1 ? SEVERITY_RANKING.length : index
}

function formatPoint(point) {
    if (!point || typeof point.line !== "number") return ""
    const column = typeof point.column === "number" ? `:C${point.column}` : ""
    return `L${point.line}${column}`
}

function formatRange(loc) {
    if (!loc) return ""
    const start = formatPoint(loc.start || loc)
    const end = formatPoint(loc.end || loc)
    if (start && end && start !== end) return `${start} → ${end}`
    return start || end
}

function normalizeSnippet(snippet) {
    if (!snippet) return ""
    return String(snippet).replace(/\r\n?/g, "\n").trim()
}

function renderSnippetBlock(snippet) {
    const normalized = normalizeSnippet(snippet)
    if (!normalized) return `<div class="ui grey text">Snippet unavailable</div>`
    return `<pre><code>${ptk_utils.escapeHtml(normalized)}</code></pre>`
}

function formatTraceList(trace) {
    const steps = Array.isArray(trace) && trace.length ? trace : null
    if (!steps) return ""
    const items = steps.map((step, idx) => {
        const label = step?.kind || (idx === 0 ? "source" : (idx === steps.length - 1 ? "sink" : "step"))
        const labelHtml = `<strong>${escapeText(label)}</strong>`
        const nodeLabel = step?.label ? `<code>${ptk_utils.escapeHtml(step.label)}</code>` : ""
        const locationParts = []
        if (step?.file) locationParts.push(escapeText(step.file))
        const locText = formatRange(step?.loc)
        if (locText) locationParts.push(escapeText(locText))
        const location = locationParts.length ? `<span>${locationParts.join(" ")}</span>` : ""
        const chunks = [labelHtml]
        if (nodeLabel) chunks.push(nodeLabel)
        if (location) chunks.push(location)
        return `<li>${chunks.join(" - ")}</li>`
    }).join("")
    return `<ul class="sast-trace-list">${items}</ul>`
}

function normalizeTraceLabel(label) {
    if (!label) return ""
    const compact = String(label).replace(/\s+/g, " ").trim()
    if (compact.length <= 140) return compact
    return `${compact.slice(0, 137)}...`
}

function formatTraceEntriesForExport(trace) {
    const steps = Array.isArray(trace) && trace.length ? trace : null
    if (!steps) {
        if (trace) {
            return [{ stage: "step", label: normalizeTraceLabel(trace), file: "", loc: "" }]
        }
        return []
    }
    return steps.map((step, idx) => {
        const stage = step?.kind || (idx === 0 ? "source" : (idx === steps.length - 1 ? "sink" : "step"))
        const label = normalizeTraceLabel(step?.label || "")
        const file = step?.file ? String(step.file) : ""
        const loc = formatRange(step?.loc)
        return { stage, label, file, loc }
    }).filter(entry => entry.stage || entry.label || entry.file || entry.loc)
}

function safeHttpLink(url) {
    if (!url) return ""
    try {
        const parsed = new URL(url)
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            return parsed.href
        }
    } catch (e) {
        return ""
    }
    return ""
}

function renderReferenceLinks(links = {}) {
    let entries = []
    if (Array.isArray(links)) {
        entries = links
            .map(item => {
                const href = typeof item === "string" ? item : (item?.url || item?.href || "")
                const safeHref = safeHttpLink(href)
                if (!safeHref) return null
                return `<li><a target="_blank" rel="noopener noreferrer" href="${ptk_utils.escapeHtml(safeHref)}">${ptk_utils.escapeHtml(safeHref)}</a></li>`
            })
            .filter(Boolean)
    } else {
        entries = Object.entries(links)
            .map(([label, href]) => {
                const safeHref = safeHttpLink(href)
                if (!safeHref) return null
                return `<li><a target="_blank" rel="noopener noreferrer" href="${ptk_utils.escapeHtml(safeHref)}">${ptk_utils.escapeHtml(safeHref)}</a></li>`
            })
            .filter(Boolean)
    }
    if (!entries.length) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>References</strong></div>
                <ul>${entries.join("")}</ul>
            </div>`
}

function renderMappingSection(cweList, owaspList) {
    const cwe = normalizeCweEntries(cweList)
    const owaspRaw = normalizeOwaspEntries(owaspList)
    const owasp = Array.from(new Set(owaspRaw))
    if (!cwe.length && !owasp.length) return ""
    const cweText = cwe.length ? `${cwe.join(", ")}` : ""
    const owaspText = owasp.length ? `${owasp.join(", ")}` : ""
    const parts = [
        cweText ? `<div><strong>CWE:</strong> ${escapeText(cweText)}</div>` : "",
        owaspText ? `<div><strong>OWASP:</strong> ${escapeText(owaspText)}</div>` : ""
    ].filter(Boolean)
    if (!parts.length) return ""
    return `<div class="sast-section" style="margin-bottom: 8px;">${parts.join("")}</div>`
}

function buildEndpointColumn(label, endpoint, nameKey, fileKey, locKey, snippetKey) {
    if (!endpoint) return ""
    const name = endpoint[nameKey] || endpoint.label
    const file = endpoint[`${fileKey}Full`] || endpoint[fileKey]
    const loc = endpoint[locKey]
    const snippet = endpoint[snippetKey]

    return `<div class="column">
                <div class="ui segment" style="overflow: overlay;">
                    <div class="ui tiny header">${escapeText(label)}</div>
                    <div><b>Name:</b> ${escapeText(name)}</div>
                    <div><b>File:</b> ${escapeText(file)}</div>
                    <div><b>Location:</b> ${escapeText(formatRange(loc), "-")}</div>
                    ${renderSnippetBlock(snippet)}
                </div>
            </div>`
}

function renderSourceSinkSections(item) {
    const source = buildEndpointColumn("Source", item.source, "sourceName", "sourceFile", "sourceLoc", "sourceSnippet")
    const sink = buildEndpointColumn("Sink", item.sink, "sinkName", "sinkFile", "sinkLoc", "sinkSnippet")
    if (!source && !sink) return ""
    return `<div class="sast-section">
                <div class="ui two column stackable grid">
                    ${source || ""}
                    ${sink || ""}
                </div>
            </div>`
}

function renderTraceSection(item) {
    const trace = item.trace && item.trace.length ? item.trace : (item.taintTrace || [])
    const traceHtml = formatTraceList(trace)
    if (!traceHtml) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Taint Trace</strong></div>
                ${traceHtml}
            </div>`
}

function renderCombinedSnippet(snippet) {
    if (!snippet) return ""
    return `<div class="sast-section">
                <div class="sast-section-title">Code Context</div>
                ${renderSnippetBlock(snippet)}
            </div>`
}

function renderSastFinding(item, index) {
    const severityMeta = getSeverityMeta(item.metadata?.severity || item.severity)
    const severityAttr = ptk_utils.escapeHtml(String(item.metadata?.severity || item.severity || "").toLowerCase())
    const ruleName = item.metadata?.name || item.name || item.module_metadata?.name || `Finding #${index + 1}`
    const ruleNumberLabel = `Rule ${index + 1}`
    const ruleId = item.metadata?.id || item.rule_id || item.module_metadata?.id || "N/A"
    const moduleName = item.module_metadata?.name || item.module_metadata?.id || ""
    const confidence = resolveConfidenceValue(item.confidence, item.metadata?.confidence)
    const confidenceBadge = confidence !== null ? `<span class="finding-confidence" style="float: right;">Confidence: ${Math.round(confidence)}</span>` : ""
        const description = sanitizeRichText(item.metadata?.description || item.module_metadata?.description || "")
        const recommendation = sanitizeRichText(item.metadata?.recommendation || item.module_metadata?.recommendation || "")
    const references = renderReferenceLinks(item.metadata?.links || item.module_metadata?.links || {})
    const mergedOwasp = normalizeOwaspEntries([
        ...(Array.isArray(item.owasp) ? item.owasp : (item.owasp ? [item.owasp] : [])),
        ...(Array.isArray(item.metadata?.owasp) ? item.metadata.owasp : (item.metadata?.owasp ? [item.metadata.owasp] : [])),
        ...(Array.isArray(item.module_metadata?.owasp) ? item.module_metadata.owasp : (item.module_metadata?.owasp ? [item.module_metadata.owasp] : [])),
        ...(Array.isArray(item.owaspLegacy) ? item.owaspLegacy : (item.owaspLegacy ? [item.owaspLegacy] : []))
    ])
    const mappingSection = renderMappingSection(item.cwe || item.metadata?.cwe || item.module_metadata?.cwe, mergedOwasp)
    const color = severityMeta.color || ""
    return `
        <div class="card sast-report-card" data-index="${index}" data-severity="${severityAttr}" style="width: 100%;">
            <div class="content">
                <div class="ui ${color} message" style="margin-bottom: 0px;">
                    <div class="header">
                        ${severityMeta.icon}
                        <span class="sast-rule-number">${escapeText(ruleNumberLabel)}:</span>
                        ${escapeText(ruleName)}
                        ${confidenceBadge}
                    </div>

                            <p><b>Rule:</b> ${escapeText(ruleId)}</span>
                            ${moduleName ? `<span><b>Module:</b> ${escapeText(moduleName)}</p>` : ""}

                </div>

                ${renderSourceSinkSections(item)}
                ${renderTraceSection(item)}
                ${description ? `<div class="sast-section"><div class="sast-section-title"><strong>Description</strong></div>${description}</div>` : ""}
                ${recommendation ? `<div class="sast-section" style="margin-top: 8px;"><div class="sast-section-title"><strong>Recommendation</strong></div>${recommendation}</div>` : ""}
                ${mappingSection}
                ${references}
            </div>
        </div>
    `
}

function getIastEvidence(item) {
    if (!item || !item.evidence) return null
    if (item.evidence.iast && typeof item.evidence.iast === "object") {
        return item.evidence.iast
    }
    if (Array.isArray(item.evidence)) {
        return item.evidence.find(e => e && typeof e === "object") || null
    }
    if (typeof item.evidence === "object") {
        return item.evidence
    }
    return null
}

function normalizeIastValue(value) {
    if (value === undefined || value === null) return ""
    if (Array.isArray(value)) {
        return value.map(entry => {
            if (entry === undefined || entry === null) return ""
            if (typeof entry === "string") return entry
            try {
                return JSON.stringify(entry, null, 2)
            } catch (e) {
                return String(entry)
            }
        }).filter(Boolean).join("\n")
    }
    if (typeof value === "object") {
        try {
            return JSON.stringify(value, null, 2)
        } catch (e) {
            return String(value)
        }
    }
    return String(value)
}

function renderIastMetaSection(rows = []) {
    const entries = rows
        .filter(row => row && row.value)
        .map(row => `<div><strong>${escapeText(row.label)}:</strong> ${row.value}</div>`)
    if (!entries.length) return ""
    return `<div class="sast-section iast-meta">
                ${entries.join("")}
            </div>`
}

function renderIastContextSection(context = {}, snippetValue = "") {
    const safeContext = context && typeof context === "object" ? context : {}
    const rows = []
    if (safeContext.element) rows.push(`<div><strong>Element:</strong> ${escapeText(safeContext.element)}</div>`)
    if (safeContext.elementId) rows.push(`<div><strong>Element ID:</strong> ${escapeText(safeContext.elementId)}</div>`)
    if (safeContext.domPath) rows.push(`<div><strong>DOM Path:</strong> <code>${ptk_utils.escapeHtml(String(safeContext.domPath))}</code></div>`)
    if (safeContext.position) rows.push(`<div><strong>Position:</strong> ${escapeText(safeContext.position)}</div>`)
    if (safeContext.attribute) rows.push(`<div><strong>Attribute:</strong> ${escapeText(safeContext.attribute)}</div>`)
    const metaHtml = rows.join("")
    const snippet = snippetValue
        ? `<div class="iast-context-snippet">
                <div class="sast-section-title"><strong>Captured Value</strong></div>
                ${renderSnippetBlock(snippetValue)}
            </div>`
        : ""
    if (!metaHtml && !snippet) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Context</strong></div>
                ${metaHtml}
                ${snippet}
            </div>`
}

function renderIastFlowSection(flow = []) {
    if (!Array.isArray(flow) || !flow.length) return ""
    const nodes = flow.map((node = {}, idx) => {
        const stage = node?.stage
            ? String(node.stage).toUpperCase()
            : (idx === 0 ? "SOURCE" : (idx === flow.length - 1 ? "SINK" : `STEP ${idx + 1}`))
        const label = node?.label || node?.key || `Node ${idx + 1}`
        const op = node?.op ? `<div class="iast-flow-op">Operation: ${escapeText(node.op)}</div>` : ""
        const dom = node?.domPath ? `<div class="iast-flow-dom">DOM: <code>${ptk_utils.escapeHtml(String(node.domPath))}</code></div>` : ""
        const location = node?.location ? `<div class="iast-flow-location">${escapeText(node.location)}</div>` : ""
        return `
            <div class="iast-flow-node">
                <div class="iast-flow-stage">${escapeText(stage)}</div>
                <div class="iast-flow-details">
                    <div class="iast-flow-label"><strong>${escapeText(label)}</strong></div>
                    ${op}
                    ${dom}
                    ${location}
                </div>
            </div>
        `
    }).join("")
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Flow</strong></div>
                <div class="iast-flow-list">${nodes}</div>
            </div>`
}

function renderIastTraceSection(trace = []) {
    if (!Array.isArray(trace) || !trace.length) return ""
    const traceHtml = formatTraceList(trace)
    if (!traceHtml) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Trace</strong></div>
                ${traceHtml}
            </div>`
}

function renderIastFinding(item, index) {
    if (!item) return ""
    const evidence = getIastEvidence(item) || {}
    const raw = evidence.raw || {}
    const meta = raw.meta || {}
    const original = item.__finding || item.finding || null
    const displayIndex = typeof index === "number" && !Number.isNaN(index)
        ? index
        : (typeof item.__index === "number" ? item.__index : 0)
    const attrIndex = typeof item.__index === "number" ? item.__index : displayIndex
    const severityValue = raw.severity || item.severity || original?.severity || "info"
    const severityMeta = getSeverityMeta(severityValue)
    const ruleName = meta.ruleName || original?.ruleName || original?.category || item.category || `IAST finding #${displayIndex + 1}`
    const ruleId = raw.ruleId || original?.ruleId || ""
    const moduleName = meta.moduleName || original?.moduleName || ""
    const category = original?.category || item.category || meta.type || ""
    const routingUrl = evidence?.routing?.runtimeUrl || evidence?.routing?.url || ""
    const url = routingUrl || item.location?.url || raw.location?.url || original?.location?.url || ""
    const safeUrl = safeHttpLink(url)
    const urlDisplay = safeUrl
        ? `<a href="${ptk_utils.escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer">${ptk_utils.escapeHtml(safeUrl)}</a>`
        : (url ? escapeText(url) : "")
    const sourceLabel = evidence?.taintSource || raw.source || original?.source || "Not specified"
    const sinkLabel = evidence?.sinkId || raw.sinkId || original?.sink || "Not specified"
    const context = evidence?.context || raw.context || original?.context || {}
    const snippetValue = normalizeIastValue(context?.value ?? evidence?.matched)
    const flow = Array.isArray(context?.flow) && context.flow.length ? context.flow : []
    const trace = Array.isArray(evidence?.trace) && evidence.trace.length ? evidence.trace : []
    const description = sanitizeRichText(original?.description || meta.description || "")
    const recommendation = sanitizeRichText(original?.recommendation || meta.recommendation || "")
    const references = renderReferenceLinks(original?.links || meta.links || {})
    const mappingSection = renderMappingSection(original?.cwe || meta.cwe, resolveOwaspList(original || meta || {}))
    const confidence = resolveConfidenceValue(
        item.confidence,
        original?.confidence,
        item.metadata?.confidence,
        original?.metadata?.confidence
    )
    const severityAttr = ptk_utils.escapeHtml(String(severityValue || "").toLowerCase())
    const requestKeyAttr = item.requestKey ? ` data-request-key="${ptk_utils.escapeHtml(String(item.requestKey))}"` : ""
    const ruleMetaLine = [
        ruleId ? `<span><b>Rule:</b> ${escapeText(ruleId)}</span>` : "",
        moduleName ? `<span><b>Module:</b> ${escapeText(moduleName)}</span>` : ""
    ].filter(Boolean).join(" | ")
    const confidenceLine = confidence !== null ? `<span class="finding-confidence" style="float: right;">Confidence: ${Math.round(confidence)}</span>` : ""
    const metaSection = renderIastMetaSection([
        { label: "Source", value: escapeText(sourceLabel) },
        { label: "Sink", value: escapeText(sinkLabel) },
        { label: "Category", value: category ? escapeText(category) : "" },
        { label: "URL", value: urlDisplay }
    ])
    const contextSection = renderIastContextSection(context, snippetValue)
    const flowSection = renderIastFlowSection(flow)
    const traceSection = renderIastTraceSection(trace)
    return `
        <div class="card sast-report-card iast-report-card iast_attack_card" data-index="${attrIndex}" data-severity="${severityAttr}"${requestKeyAttr} style="width: 100%;">
            <div class="content">
                <div class="ui ${severityMeta.color} message" style="margin-bottom: 0px;">
                    <div class="header">
                        ${severityMeta.icon}
                        ${escapeText(ruleName)}
                        ${confidenceLine}
                    </div>
                    ${ruleMetaLine ? `<div class="iast-rule-meta">${ruleMetaLine}</div>` : ""}
                </div>
                ${metaSection}
                ${contextSection}
                ${flowSection || ""}
                ${traceSection || ""}
                ${(description || recommendation || references) ? `<div style="margin-top: 10px;"></div>` : ""}
                ${description ? `<div class="sast-section"><div class="sast-section-title"><strong>Description</strong></div>${description}</div>` : ""}
                ${recommendation ? `<div class="sast-section" style="margin-top: 8px;"><div class="sast-section-title"><strong>Recommendation</strong></div>${recommendation}</div>` : ""}
                ${mappingSection}
                ${references}
            </div>
        </div>
    `
}

function normalizeScaList(value) {
    if (Array.isArray(value)) return value.filter(entry => entry !== undefined && entry !== null)
    if (value === undefined || value === null || value === "") return []
    return [value]
}

function formatScaLocationValue(file) {
    if (!file) return ""
    if (typeof file === "object") {
        const candidates = [
            file.url,
            file.href,
            file.path,
            file.location,
            file.source,
            file.file
        ].filter(Boolean)
        if (candidates.length) {
            return formatScaLocationValue(candidates[0])
        }
    }
    const link = safeHttpLink(file)
    const safeText = escapeText(file)
    if (link) {
        const href = ptk_utils.escapeHtml(link)
        return `<a href="${href}" target="_blank" rel="noopener noreferrer">${safeText}</a>`
    }
    return safeText
}

function buildScaVersionRangeFromNode(node) {
    if (!node || typeof node !== "object") return ""
    const segments = []
    if (node.atOrAbove) segments.push(`>= ${node.atOrAbove}`)
    if (node.above) segments.push(`> ${node.above}`)
    if (node.atOrBelow) segments.push(`<= ${node.atOrBelow}`)
    if (node.below) segments.push(`< ${node.below}`)
    return segments.join(" , ")
}

function formatScaVersionRange(finding) {
    const direct = buildScaVersionRangeFromNode(finding)
    if (direct) return direct
    if (finding && typeof finding.vulnerable === "object") {
        const nested = buildScaVersionRangeFromNode(finding.vulnerable)
        if (nested) return nested
    }
    return ""
}

function formatScaFixedVersions(finding) {
    if (!finding || typeof finding !== "object") return ""
    const candidates = [
        finding.fixedin,
        finding.fixedIn,
        finding.fixed,
        finding.fix,
        finding.fixVersion,
        finding.fixVersions,
        finding.resolved
    ]
    const values = candidates.flatMap(normalizeScaList).map(entry => String(entry || "").trim()).filter(Boolean)
    const unique = Array.from(new Set(values))
    return unique.join(", ")
}

function formatScaCweLinks(cwe) {
    const list = normalizeScaList(cwe)
    if (!list.length) return ""
    return list.map(code => {
        const raw = String(code || "")
        const numeric = raw.replace(/[^0-9]/g, "")
        const cweId = numeric || raw
        const href = `https://cwe.mitre.org/data/definitions/${encodeURIComponent(cweId)}.html`
        return `<a href="${ptk_utils.escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${ptk_utils.escapeHtml(raw)}</a>`
    }).join(", ")
}

function formatScaCveLinks(identifiers = {}) {
    const list = normalizeScaList(identifiers.CVE || identifiers.cve)
    if (!list.length) return ""
    return list.map(cve => {
        const safe = ptk_utils.escapeHtml(String(cve || ""))
        const href = `https://www.cvedetails.com/cve/${encodeURIComponent(String(cve || ""))}/`
        return `<a href="${ptk_utils.escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${safe}</a>`
    }).join(", ")
}

function formatScaPlainList(values) {
    const list = normalizeScaList(values).map(val => escapeText(String(val || ""))).filter(Boolean)
    if (!list.length) return ""
    return list.join(", ")
}

function formatScaLicenses(licenses) {
    const list = normalizeScaList(licenses).map(entry => escapeText(String(entry || ""))).filter(Boolean)
    return list.join(", ")
}

function formatScaCvss(finding) {
    if (!finding || typeof finding !== "object") return ""
    const cvss = finding.cvss || finding.cvssV3 || {}
    const score = finding.cvssScore ?? finding.score ?? cvss.score ?? cvss.baseScore
    const vector = finding.cvssVector || cvss.vectorString || cvss.vector
    if (score && vector) return `${score} (${vector})`
    if (score) return `${score}`
    return ""
}

function renderScaVersionInfo(component, finding) {
    const rows = []
    const version = component?.version || component?.installedVersion || ""
    const latest = component?.latest || component?.latestVersion || ""
    if (version) rows.push(`<div><strong>Detected version:</strong> ${escapeText(version)}</div>`)
    if (latest) rows.push(`<div><strong>Latest version:</strong> ${escapeText(latest)}</div>`)
    const range = formatScaVersionRange(finding)
    if (range) rows.push(`<div><strong>Affected versions:</strong> <code>${ptk_utils.escapeHtml(range)}</code></div>`)
    const fixed = formatScaFixedVersions(finding)
    if (fixed) rows.push(`<div><strong>Fixed in:</strong> ${escapeText(fixed)}</div>`)
    if (!rows.length) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Version Info</strong></div>
                ${rows.join("")}
            </div>`
}

function buildScaEntries(list) {
    if (!Array.isArray(list)) return []
    const entries = []
    list.forEach(component => {
        if (!component) return
        const findings = Array.isArray(component.findings)
            ? component.findings
            : (Array.isArray(component.vulnerabilities) ? component.vulnerabilities : [])
        if (findings.length) {
            findings.forEach(finding => entries.push({ component, finding }))
            return
        }
        if (component.severity || component.identifiers || component.info) {
            entries.push({ component, finding: component })
        }
    })
    return entries
}

function cloneScaIdentifiers(raw) {
    if (!raw || typeof raw !== "object") return {}
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

function transformScaFindingForReport(finding) {
    if (!finding || (finding.engine && finding.engine !== "SCA")) return null
    const evidence = finding.evidence?.sca || {}
    const componentInfo = evidence.component || {}
    const componentName = componentInfo.name || componentInfo.component || finding.ruleName || "Dependency"
    const version = componentInfo.version || "n/a"
    const file = evidence.sourceFile || finding.location?.file || null
    const identifiers = cloneScaIdentifiers(evidence.identifiers)
    const summary = evidence.summary || identifiers.summary || finding.description || finding.ruleName || null
    if (summary && (!identifiers.summary || typeof identifiers.summary !== "string")) {
        identifiers.summary = summary
    }
    const versionRange = evidence.versionRange || {}
    const convertedFinding = {
        severity: finding.severity || "medium",
        identifiers,
        info: Array.isArray(evidence.info) ? evidence.info.slice() : [],
        cwe: finding.cwe,
        atOrAbove: versionRange.atOrAbove || null,
        above: versionRange.above || null,
        atOrBelow: versionRange.atOrBelow || null,
        below: versionRange.below || null
    }
    return {
        component: {
            component: componentName,
            version,
            file
        },
        finding: convertedFinding
    }
}

function buildScaEntriesFromFindings(findings = []) {
    if (!Array.isArray(findings)) return []
    return findings.map(transformScaFindingForReport).filter(Boolean)
}

function renderScaIdentifierSection(finding) {
    const identifiers = finding?.identifiers || {}
    const fragments = []
    const cves = formatScaCveLinks(identifiers)
    if (cves) fragments.push(`<div><strong>CVE:</strong> ${cves}</div>`)
    const githubIds = formatScaPlainList(identifiers.githubID || identifiers.GHSA)
    if (githubIds) fragments.push(`<div><strong>GitHub:</strong> ${githubIds}</div>`)
    const issues = formatScaPlainList(identifiers.issue)
    if (issues) fragments.push(`<div><strong>Issue:</strong> ${issues}</div>`)
    const prs = formatScaPlainList(identifiers.PR)
    if (prs) fragments.push(`<div><strong>PR:</strong> ${prs}</div>`)
    const retid = identifiers.retid ? escapeText(String(identifiers.retid)) : ""
    if (retid) fragments.push(`<div><strong>ID:</strong> ${retid}</div>`)
    const cweLinks = formatScaCweLinks(finding?.cwe)
    if (cweLinks) fragments.push(`<div><strong>CWE:</strong> ${cweLinks}</div>`)
    if (!fragments.length) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Identifiers</strong></div>
                ${fragments.join("")}
            </div>`
}

function renderScaReferencesSection(finding) {
    const refs = normalizeScaList(finding?.info || finding?.references || finding?.urls)
        .map(ref => (typeof ref === "string" ? ref.trim() : ""))
        .filter(Boolean)
    if (!refs.length) return ""
    const linkMap = {}
    refs.forEach((href, idx) => {
        linkMap[`Reference ${idx + 1}`] = href
    })
    return renderReferenceLinks(linkMap)
}

function renderScaFinding(entry, index) {
    if (!entry) return ""
    const component = entry.component || {}
    const finding = entry.finding || {}
    const severityMeta = getSeverityMeta(finding.severity)
    const confidence = resolveConfidenceValue(finding?.confidence, finding?.confidence_score, finding?.metadata?.confidence)
    const confidenceBadge = confidence !== null ? `<span class="finding-confidence" style="float: right;">Confidence: ${Math.round(confidence)}</span>` : ""
    const severityAttr = ptk_utils.escapeHtml(String(finding.severity || "").toLowerCase())
    const summary = finding?.identifiers?.summary || finding.summary || `Component vulnerability #${index + 1}`
    const componentName = component.component || component.name || component.library || component.package || component.module || "Unknown component"
    const version = component.version || component.installedVersion || component.libraryVersion || component.currentVersion || ""
    const fileValue = formatScaLocationValue(component.file || component.path || component.location)
    const licenses = formatScaLicenses(component.licenses)
    const cvss = formatScaCvss(finding)
    const metaRows = []
    metaRows.push({ label: "Component", value: escapeText(componentName) })
    if (version) metaRows.push({ label: "Version", value: escapeText(version) })
    if (fileValue) metaRows.push({ label: "File", value: fileValue })
    if (licenses) metaRows.push({ label: "Licenses", value: licenses })
    if (cvss) metaRows.push({ label: "CVSS", value: escapeText(cvss) })
    const metaSection = renderIastMetaSection(metaRows)
    const versionSection = renderScaVersionInfo(component, finding)
    const identifierSection = renderScaIdentifierSection(finding)
    const referencesSection = renderScaReferencesSection(finding)
    const mappingSection = renderMappingSection(finding.cwe || finding?.identifiers?.cwe, finding.owasp || finding?.identifiers?.owasp)
    const description = sanitizeRichText(finding.description || finding?.identifiers?.description || "")
    const recommendation = sanitizeRichText(finding.recommendation || finding?.identifiers?.recommendation || "")
    return `
        <div class="card sast-report-card sca-report-card" data-index="${index}" data-severity="${severityAttr}" style="width: 100%;">
            <div class="content">
                <div class="ui ${severityMeta.color} message" style="margin-bottom: 0px;">
                    <div class="header">
                        ${severityMeta.icon}
                        ${escapeText(summary)}
                        ${confidenceBadge}
                    </div>
                    ${componentName ? `<div><b>Package:</b> ${escapeText(componentName)}</div>` : ""}
                </div>
                ${metaSection}
                ${versionSection}
                ${identifierSection}
                ${description ? `<div class="sast-section"><div class="sast-section-title"><strong>Description</strong></div>${description}</div>` : ""}
                ${recommendation ? `<div class="sast-section" style="margin-top: 8px;"><div class="sast-section-title"><strong>Recommendation</strong></div>${recommendation}</div>` : ""}
                ${mappingSection}
                ${referencesSection}
            </div>
        </div>
    `
}

function buildRawResponse(response = {}) {
    const parts = []
    const headersBlock = Array.isArray(response.headers) && response.headers.length
        ? response.headers.map(h => `${h.name}: ${h.value}`).join('\n')
        : ''
    if (response.statusLine) parts.push(response.statusLine)
    if (headersBlock) parts.push(headersBlock)
    if (parts.length) parts.push('')
    parts.push(typeof response.body === 'string' ? response.body : '')
    return parts.join('\n')
}

function resolveDastAttackContext(finding, viewModel) {
    const evidence = finding?.evidence?.dast || {}
    const requests = Array.isArray(viewModel?.requests) ? viewModel.requests : []
    const requestRecord = evidence.requestId != null
        ? requests.find((record) => String(record.id) === String(evidence.requestId))
        : null
    const attackRecord = requestRecord && evidence.attackId != null
        ? (requestRecord.attacks || []).find((attack) => String(attack.id) === String(evidence.attackId))
        : null
    return { requestRecord, attackRecord }
}

function mapDastFindingToLegacy(finding, viewModel) {
    const severity = String(finding?.severity || "medium")
    const severityTitle = severity.charAt(0).toUpperCase() + severity.slice(1)
    const { requestRecord, attackRecord } = resolveDastAttackContext(finding, viewModel)
    const meta = attackRecord?.metadata || finding?.metadata || {}
    const cwe = finding?.cwe || meta.cwe || []
    const owasp = finding?.owasp || meta.owasp || []
    const originalSchema = requestRecord?.original || {}
    const request = originalSchema.request
        ? JSON.parse(JSON.stringify(originalSchema.request))
        : { raw: "", url: finding?.location?.url || "", method: finding?.location?.method || "GET" }
    if (!request.raw) {
        const method = request.method || "GET"
        const url = request.url || "/"
        request.raw = `${method} ${url} HTTP/1.1`
    }
    const response = attackRecord?.response
        ? JSON.parse(JSON.stringify(attackRecord.response))
        : (originalSchema.response ? JSON.parse(JSON.stringify(originalSchema.response)) : {})
    response.raw = buildRawResponse(response)
    const proof = attackRecord?.proof || ""
    return {
        info: {
            metadata: {
                name: finding?.ruleName || finding?.vulnId || finding?.category || "Finding",
                severity: severityTitle,
                confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null,
                description: finding?.description || meta.description || "",
                recommendation: finding?.recommendation || meta.recommendation || "",
                links: finding?.links || meta.links || {},
                cwe,
                owasp
            },
            proof,
            request,
            response,
            success: true,
            confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null
        },
        original: {
            request,
            response
        }
    }
}

function mapSastFindingToLegacy(finding) {
    const severity = String(finding?.severity || "medium")
    const severityTitle = severity.charAt(0).toUpperCase() + severity.slice(1)
    const evidence = finding?.evidence?.sast || {}
    const defaultSnippet = evidence.codeSnippet || ""
    const owaspList = normalizeOwaspEntries([
        ...(Array.isArray(finding?.owasp) ? finding.owasp : (finding?.owasp ? [finding.owasp] : [])),
        ...(Array.isArray(finding?.owaspLegacy) ? finding.owaspLegacy : (finding?.owaspLegacy ? [finding.owaspLegacy] : []))
    ])
    const cweList = normalizeCweEntries(finding?.cwe)
    const source = evidence.source || {
        sourceName: finding?.source || finding?.ruleName || "Source",
        sourceFile: finding?.location?.file || "",
        sourceFileFull: finding?.location?.file || "",
        sourceLoc: null,
        sourceSnippet: defaultSnippet
    }
    const sink = evidence.sink || {
        sinkName: finding?.ruleName || "Sink",
        sinkFile: finding?.location?.file || "",
        sinkFileFull: finding?.location?.file || "",
        sinkLoc: null,
        sinkSnippet: defaultSnippet
    }
    return {
        metadata: {
            id: finding?.ruleId || "",
            name: finding?.ruleName || finding?.vulnId || "Finding",
            severity: severityTitle,
            description: finding?.description || "",
            recommendation: finding?.recommendation || "",
            links: finding?.links || {},
            confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null,
            owasp: owaspList,
            cwe: cweList
        },
        module_metadata: {
            id: finding?.moduleId || "",
            name: finding?.moduleName || "",
            severity: severityTitle,
            category: finding?.category || "",
            owasp: owaspList,
            cwe: cweList,
            description: "",
            recommendation: "",
            links: {}
        },
        source,
        sink,
        trace: evidence.trace || finding?.trace || [],
        codeSnippet: evidence.codeSnippet || defaultSnippet,
        pageUrl: finding?.location?.pageUrl || finding?.location?.file || ""
    }
}

function mapIastFindingToLegacy(finding, index) {
    const severity = finding?.severity || "medium"
    const evidence = finding?.evidence?.iast || {}
    const context = {
        domPath: evidence.domPath || finding?.location?.domPath || null,
        elementId: finding?.location?.elementId || null,
        value: evidence.value || null,
        flow: evidence.flow || []
    }
    const raw = {
        meta: {
            ruleName: finding?.ruleName || finding?.category || "IAST Finding",
            moduleId: finding?.moduleId || null,
            moduleName: finding?.moduleName || null
        },
        severity,
        type: finding?.category || null,
        ruleId: finding?.ruleId || null,
        sinkId: evidence.sinkId || null,
        source: evidence.taintSource || null,
        context,
        matched: evidence.matched || null
    }
    return {
        __index: index,
        severity,
        category: finding?.category || null,
        location: { url: finding?.location?.url || null },
        requestKey: null,
        evidence: [{
            source: "IAST",
            raw,
            sinkId: evidence.sinkId || null,
            taintSource: evidence.taintSource || null,
            context,
            trace: context.flow
        }],
        confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null,
        success: true,
        __finding: finding
    }
}

jQuery(function () {
    // -- Dashboard -- //
    index_controller = new ptk_controller_index()
    const sca_controller = new ptk_controller_sca()
    const rattacker_controller = new ptk_controller_rattacker()
    const iast_controller = new ptk_controller_iast()
    const sast_controller = new ptk_controller_sast()


    $('#filter_all').on("click", function () {
        $('.attack_info').show()
        $('#filter_vuln').removeClass('active')
        $('#filter_all').addClass('active')
    })

    $('#filter_vuln').on("click", function () {
        $('.attack_info.nonvuln').hide()
        $('#filter_all').removeClass('active')
        $('#filter_vuln').addClass('active')
    })

    $('#print').on("click", function () {
        window.print()
    })

    $('#export_pdf_btn').on("click", function () {
        exportSelected("pdf")
    })
    $('#export_md_btn').on("click", function () {
        exportSelected("markdown")
    })

    $(document).on("change", ".severity-filter", function () {
        if (severitySyncGuard) return
        const engine = $(this).data("engine")
        const severity = $(this).data("severity")
        const checked = $(this).is(":checked")
        syncSeverityCheckboxes(engine, severity, checked)
        applySeverityFilter(engine)
        updateSummarySegment()
    })

    $('.icon.hideshowreport').on("click", function () {
        if ($(this).hasClass('minus')) {
            $(this).removeClass('minus')
            $(this).addClass('plus')
            $(this).parent().next().hide()
        } else {
            $(this).removeClass('plus')
            $(this).addClass('minus')
            $(this).parent().next().show()
        }
    })

    if ($.fn.checkbox) {
        $('.ptk-severity-filter .ui.checkbox').checkbox()
        $('#pdf_include_sensitive').closest('.ui.checkbox').checkbox()
    }
    if ($.fn.dropdown) {
        $('#report_preset').dropdown()
    }

    setReportView($('#report_preset').val())

    $('#report_preset').on("change", function () {
        setReportView($(this).val())
    })

    async function bindInfo(host) {
        if (host) {
            $('#dashboard_message_text').html('<h2>OWASP PTK Security Report</h2>  ' + host)
            setExportMeta({ host })
        } else {
            $('#dashboard_message_text').html(`Reload the tab to activate tracking &nbsp;<i class="exclamation red  circle  icon"></i>`)
        }
    }

    async function bindOWASP() {
        const tab = index_controller.tab || {}
        let raw = tab.findings ? tab.findings : new Array()
        let dt = raw.map(item => [item[0]])
        let params = { "data": dt, "columns": [{ width: "100%" }] }
        let table = bindTable('#tbl_owasp', params)
        table.columns.adjust().draw()
        $('.loader.owasp').hide()
        updateReportDashboardVisibility()
        markDashboardPartReady("owasp")
    }

    async function bindCVEs() {
        let dt = new Array()
        const tab = index_controller.tab || {}
        if (Array.isArray(tab.cves)) {
            tab.cves.forEach(item => {
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
        let params = { "data": dt }
        bindTable('#tbl_cves', params)
        $('.loader.cves').hide()
        updateReportDashboardVisibility()
        markDashboardPartReady("cves")
    }

    async function bindTechnologies() {
        let dt = new Array()
        const tab = index_controller.tab || {}
        if (tab.technologies)
            Object.values(tab.technologies).forEach(item => {
                dt.push([item.name, item.version, item.category || ''])
            })
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
        updateReportDashboardVisibility()
        markDashboardPartReady("technologies")
    }


    function bindCookies() {
        const tab = index_controller.tab || {}
        if (tab.cookies && Object.keys(tab.cookies).length) {
            $("a[data-tab='cookie']").show()
            $('#tbl_storage').DataTable().row.add(['Cookie', `<a href="#" class="storage_auth_link" data="cookie">View</a>`]).draw()


            let dt = new Array()
            Object.values(tab.cookies).forEach(item => {
                //Object.values(domain).forEach(item => {
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
                                '<tr class="group" ><td colspan="3"><div class="ui grey ribbon label">' + group + '</div></td></tr>'
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
        updateReportDashboardVisibility()
        markDashboardPartReady("cookies")
    }

    async function bindTokens(data) {
        if (tokens.length > 0) {
            $("div[data-tab='tokens']").show()
            if (!tokenAdded) {
                $('#tbl_storage').DataTable().row.add(['Tokens', `<a href="#" class="storage_auth_link" data="tokens">View</a>`]).draw()
                tokenAdded = true
            }
            $("a[data-tab='tokens']").show()
            bindTable('#tbl_tokens', { data: tokens })
        }
    }

    function bindStorage() {
        let dt = new Array()
        const tab = index_controller.tab || {}
        const storage = tab.storage || {}
        Object.keys(storage).forEach(key => {
            let item = JSON.parse(storage[key])
            if (Object.keys(item).length > 0 && item[key] != "") {
                $(document).trigger("bind_" + key, item)
                $("a[data-tab='" + key + "']").show()
                let link = `<a href="#" class="storage_auth_link" data="${key}">View</a>`
                dt.push([key, link])
            }
        })
        for (let i = 0; i < dt.length; i++) {
            $('#tbl_storage').DataTable().row.add([dt[i][0], dt[i][1]]).draw()
        }
        $('.loader.storage').hide()

        bindTokens()
        updateReportDashboardVisibility()
        markDashboardPartReady("storage")
    }

    function bindHeaders() {
        const tab = index_controller.tab || {}
        if (tab.requestHeaders && Object.keys(tab.requestHeaders).length) {
            let dt = new Array()
            Object.keys(tab.requestHeaders).forEach(name => {
                if (name.startsWith('x-') || name == 'authorization' || name == 'cookie') {
                    dt.push([name, tab.requestHeaders[name][0]])
                }
            })
            let params = {
                data: dt
            }

            bindTable('#tbl_headers', params)

            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.headersRegex)
            if (jwtToken) {
                try {
                    let jwt = JSON.parse(decodedToken)
                    tokens.push(['headers', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
                } catch (e) { }
            }
            bindTokens()
            updateReportDashboardVisibility()
        }
        markDashboardPartReady("headers")
    }

    function reportHasCardData() {
        const tab = index_controller.tab || {}
        const hasTech = Array.isArray(tab.technologies) && tab.technologies.length > 0
        const hasWaf = Array.isArray(tab.waf) ? tab.waf.length > 0 : !!tab.waf
        const hasCves = Array.isArray(tab.cves) && tab.cves.length > 0
        const hasOwasp = Array.isArray(tab.findings) && tab.findings.length > 0
        const hasHeaders = tab.requestHeaders && Object.keys(tab.requestHeaders).length > 0
        const hasStorage = tab.storage && Object.keys(tab.storage).length > 0
        const hasCookies = tab.cookies && Object.keys(tab.cookies).length > 0
        return hasTech || hasWaf || hasCves || hasOwasp || hasHeaders || hasStorage || hasCookies
    }

    function updateReportDashboardVisibility() {
        if (reportHasCardData()) {
            $('#dashboard').show()
        } else {
            $('#dashboard').hide()
        }
    }


    $(document).on("bind_localStorage", function (e, item) {
        if (Object.keys(item).length > 0) {
            $("div[data-tab='localStorage']").show()
            let output = JSON.stringify(item, null, 4)
            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(item), jwtHelper.storageRegex)
            if (jwtToken) {
                let jwt = JSON.parse(decodedToken)
                tokens.push(['localStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
            }
            $('#localStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
        }
    })

    $(document).on("bind_sessionStorage", function (e, item) {
        if (Object.keys(item).length > 0) {
            $("div[data-tab='sessionStorage']").show()
            let output = JSON.stringify(item, null, 4)
            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(item), jwtHelper.storageRegex)
            if (jwtToken) {
                let jwt = JSON.parse(decodedToken)
                tokens.push(['localStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
            }
            $('#sessionStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
        }
    })

    // -- IAST -- //

    function generateIAST(result) {
        const scanResult = result?.scanResult
        if (!scanResult) {
            replaceSectionFindings("iast", [])
            markSectionReady("iast")
            return
        }
        const vm = normalizeScanResult(scanResult)
        result.scanViewModel = vm

        const findings = Array.isArray(vm.findings) ? vm.findings : []
        const stats = vm.stats || scanResult.stats || {}
        if (!findings.length && (!Array.isArray(scanResult.items) || !scanResult.items.length)) {
            $('.loader.iast').hide()
            replaceSectionFindings("iast", [])
            markSectionReady("iast")
            return
        }

        $('#iast_report').show()
        $('#iast_report #vulns_count').text(stats.findingsCount ?? findings.length ?? 0)
        $('#iast_report #critical_count').text(stats.critical ?? scanResult.stats?.critical ?? 0)
        $('#iast_report #high_count').text(stats.high ?? scanResult.stats?.high ?? 0)
        $('#iast_report #medium_count').text(stats.medium ?? scanResult.stats?.medium ?? 0)
        $('#iast_report #low_count').text(stats.low ?? scanResult.stats?.low ?? 0)
        $('#iast_report #info_count').text(stats.info ?? scanResult.stats?.info ?? 0)

        const $container = $("#iast_report_items")
        $container.html("")

        const sortBySeverity = (a, b) => {
            const left = a?.severity || a?.metadata?.severity || "info"
            const right = b?.severity || b?.metadata?.severity || "info"
            return severityRank(left) - severityRank(right)
        }

        if (findings.length) {
            const mapped = findings.map((finding, idx) => {
                const legacy = mapIastFindingToLegacy(finding, idx)
                legacy.__finding = finding
                return legacy
            })
            mapped.sort(sortBySeverity)
            mapped.forEach((legacy, displayIndex) => {
                $container.append(renderIastFinding(legacy, displayIndex))
            })
            const exportFindings = findings.map(finding => buildExportFindingFromNormalized(finding, vm))
            replaceSectionFindings("iast", exportFindings)
        } else if (Array.isArray(scanResult.items) && scanResult.items.length) {
            const legacyItems = scanResult.items.map((item, idx) => {
                if (typeof item !== "object") return null
                const clone = { ...item }
                clone.__index = idx
                return clone
            }).filter(Boolean)
            legacyItems.sort(sortBySeverity)
            legacyItems.forEach((item, displayIndex) => {
                $container.append(renderIastFinding(item, displayIndex))
            })
            const exportFindings = legacyItems.map(item => ({
                engine: "IAST",
                severity: normalizeExportSeverity(item?.metadata?.severity || item?.severity),
                confidence: resolveConfidenceValue(item?.confidence, item?.metadata?.confidence),
                title: item?.metadata?.name || item?.name || "Finding",
                description: item?.metadata?.description || item?.description || "",
                recommendation: item?.metadata?.recommendation || item?.recommendation || "",
                location: {
                    url: item?.location?.url || item?.url || null
                },
                evidence: {
                    requestSnippet: truncateSnippet(item?.request?.raw || ""),
                    responseSnippet: truncateSnippet(item?.response?.raw || ""),
                    codeSnippet: "",
                    notes: truncateSnippet(item?.proof || ""),
                    proof: truncateSnippet(resolveIastProof(item?.evidence?.iast || item?.evidence || {}, item?.context || {})),
                    flow: normalizeIastFlowForExport(item?.context?.flow || ""),
                    trace: normalizeTraceForExport(item?.trace || item?.taintTrace || ""),
                    source: item?.source || item?.taintSource || "",
                    sink: item?.sink || item?.sinkId || "",
                    url: item?.location?.url || item?.url || "",
                    category: item?.category || item?.metadata?.category || "",
                    evidenceFullAvailable: !!(item?.request?.raw || item?.response?.raw)
                },
                references: buildReferenceList(item?.links || item?.metadata?.links || {}),
                cwe: Array.isArray(item?.metadata?.cwe) ? item.metadata.cwe : (item?.metadata?.cwe ? [item.metadata.cwe] : []),
                owasp: resolveOwaspList(item)
            }))
            replaceSectionFindings("iast", exportFindings)
        } else {
            $('.loader.iast').hide()
            replaceSectionFindings("iast", [])
            markSectionReady("iast")
            return
        }

        $(".content.stacktrace").show()
        $('.loader.iast').hide()
        markSectionReady("iast")
        applySeverityFilter("iast")
    }

    // -- SAST -- //

    function generateSAST(result) {
        const scanResult = result?.scanResult
        if (!scanResult) {
            replaceSectionFindings("sast", [])
            markSectionReady("sast")
            return
        }
        const vm = normalizeScanResult(scanResult)
        result.scanViewModel = vm
        const findings = Array.isArray(vm.findings) ? vm.findings : []
        const legacyItems = Array.isArray(scanResult.items) ? scanResult.items : []
        if (!findings.length && !legacyItems.length) {
            $('.loader.sast').hide()
            replaceSectionFindings("sast", [])
            markSectionReady("sast")
            return
        }
        $('#sast_report').show()

        const ruleIds = new Set()
        const addRuleId = (item) => {
            if (!item) return
            const candidates = [
                item.ruleId,
                item.rule_id,
                item.metadata?.id,
                item.module_metadata?.id,
                item.moduleId
            ]
            const id = candidates.find(value => value !== undefined && value !== null && String(value).trim())
            if (id) ruleIds.add(String(id).trim())
        }

        const $container = $("#sast_report_items")
        $container.html("")
        if (findings.length) {
            const mapped = findings.map(mapSastFindingToLegacy)
            mapped.sort((a, b) => severityRank(a.metadata?.severity) - severityRank(b.metadata?.severity))
            mapped.forEach((item, index) => {
                $container.append(renderSastFinding(item, index))
                addRuleId(item)
            })
            const exportFindings = findings.map(finding => buildExportFindingFromNormalized(finding, vm))
            replaceSectionFindings("sast", exportFindings)
        } else {
            const sortedItems = [...legacyItems].sort((a, b) => {
                const aSeverity = a.metadata?.severity || a.severity
                const bSeverity = b.metadata?.severity || b.severity
                return severityRank(aSeverity) - severityRank(bSeverity)
            })
            sortedItems.forEach((item, index) => {
                $container.append(renderSastFinding(item, index))
                addRuleId(item)
            })
            const exportFindings = sortedItems.map(item => ({
                engine: "SAST",
                severity: normalizeExportSeverity(item?.metadata?.severity || item?.severity),
                confidence: resolveConfidenceValue(item?.confidence, item?.metadata?.confidence),
                title: item?.metadata?.name || item?.metadata?.rule_id || item?.name || "Finding",
                description: item?.metadata?.description || item?.description || "",
                recommendation: item?.metadata?.recommendation || item?.recommendation || "",
                location: {
                    file: item?.source?.sourceFile || item?.sink?.sinkFile || item?.location?.file || null,
                    line: item?.source?.sourceLoc?.start?.line || item?.sink?.sinkLoc?.start?.line || null,
                    column: item?.source?.sourceLoc?.start?.column || item?.sink?.sinkLoc?.start?.column || null
                },
                evidence: {
                    requestSnippet: "",
                    responseSnippet: "",
                    codeSnippet: truncateSnippet(item?.source?.sourceSnippet || item?.sink?.sinkSnippet || ""),
                    notes: "",
                    trace: normalizeTraceForExport(item?.trace || item?.taintTrace || item?.metadata?.trace || ""),
                    source: normalizeEndpointDetails(item?.source || null),
                    sink: normalizeEndpointDetails(item?.sink || null),
                    evidenceFullAvailable: !!(item?.source?.sourceSnippet || item?.sink?.sinkSnippet)
                },
                references: buildReferenceList(item?.links || item?.metadata?.links || {}),
                cwe: Array.isArray(item?.metadata?.cwe) ? item.metadata.cwe : (item?.metadata?.cwe ? [item.metadata.cwe] : []),
                owasp: resolveOwaspList(item)
            }))
            replaceSectionFindings("sast", exportFindings)
        }

        const stats = vm.stats || scanResult.stats || {}
        const computedRulesCount = ruleIds.size
        const resolvedRulesCount = computedRulesCount || stats.rulesCount || 0
        stats.rulesCount = resolvedRulesCount
        $('#sast_report #sast_rules_count').text(resolvedRulesCount)
        $('#sast_report #vulns_count').text(stats.findingsCount ?? findings.length ?? 0)
        $('#sast_report #critical_count').text(stats.critical ?? scanResult.stats?.critical ?? 0)
        $('#sast_report #high_count').text(stats.high ?? scanResult.stats?.high ?? 0)
        $('#sast_report #medium_count').text(stats.medium ?? scanResult.stats?.medium ?? 0)
        $('#sast_report #low_count').text(stats.low ?? scanResult.stats?.low ?? 0)
        $('#sast_report #info_count').text(stats.info ?? scanResult.stats?.info ?? 0)

        $(".content.stacktrace").show()
        $('.loader.sast').hide()
        markSectionReady("sast")
        applySeverityFilter("sast")
    }


    // -- SCA -- //

    function generateSCA(result) {
        const scanResult = result?.scanResult
        if (!scanResult) {
            replaceSectionFindings("sca", [])
            markSectionReady("sca")
            return
        }
        const rawFindings = Array.isArray(scanResult.findings) ? scanResult.findings : []
        const looksLikeFlatFindings = rawFindings.some(entry => entry?.engine === "SCA" || entry?.evidence?.sca)
        const rawComponents = looksLikeFlatFindings
            ? []
            : (Array.isArray(scanResult.items) ? scanResult.items : [])
        if ((!rawComponents.length && !rawFindings.length) || (Array.isArray(scanResult.findings) && scanResult.findings.length === 0)) {
            $('.loader.sca').hide()
            replaceSectionFindings("sca", [])
            markSectionReady("sca")
            return
        }

        const $container = $("#sca_report_items")
        $container.html("")

        const entries = looksLikeFlatFindings
            ? buildScaEntriesFromFindings(rawFindings)
            : buildScaEntries(rawComponents)
        if (!entries.length) {
            $('.loader.sca').hide()
            replaceSectionFindings("sca", [])
            markSectionReady("sca")
            return
        }

        $('#sca_report').show()
        if (entries.length) {
            entries.sort((a, b) => severityRank(a?.finding?.severity) - severityRank(b?.finding?.severity))
            entries.forEach((entry, index) => {
                $container.append(renderScaFinding(entry, index))
            })
        }
        const exportFindings = entries.map(entry => buildExportFindingFromSca(entry))
        replaceSectionFindings("sca", exportFindings)

        const computedStats = {
            findingsCount: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        }
        const bucketSeverity = (value) => {
            const normalized = String(value || '').toLowerCase()
            if (normalized === 'critical') return 'critical'
            if (normalized === 'high') return 'high'
            if (normalized === 'medium') return 'medium'
            if (normalized === 'low') return 'low'
            return 'info'
        }
        rawComponents.forEach(component => {
            const vulns = Array.isArray(component?.findings)
                ? component.findings
                : (Array.isArray(component?.vulnerabilities) ? component.vulnerabilities : [])
            if (!vulns.length && component?.severity) {
                computedStats.findingsCount += 1
                const key = bucketSeverity(component.severity)
                computedStats[key] += 1
                return
            }
            vulns.forEach(vuln => {
                computedStats.findingsCount += 1
                const key = bucketSeverity(vuln?.severity)
                computedStats[key] += 1
            })
        })

        const stats = scanResult.stats || computedStats
        $('#sca_report #vulns_count').text(stats.findingsCount ?? computedStats.findingsCount)
        $('#sca_report #critical_count').text(stats.critical ?? computedStats.critical)
        $('#sca_report #high_count').text(stats.high ?? computedStats.high)
        $('#sca_report #medium_count').text(stats.medium ?? computedStats.medium)
        $('#sca_report #low_count').text(stats.low ?? computedStats.low)
        $('#sca_report #info_count').text(stats.info ?? computedStats.info)
        $('.loader.sca').hide()
        markSectionReady("sca")
        applySeverityFilter("sca")
    }

    // -- R-Attacker -- //

    function generateRattacker(result) {
        const scanResult = result?.scanResult
        if (!scanResult) {
            replaceSectionFindings("dast", [])
            markSectionReady("rattacker")
            return
        }

        const vm = normalizeScanResult(scanResult)
        result.scanViewModel = vm

        const findings = Array.isArray(vm.findings) ? vm.findings : []
        const stats = vm.stats || scanResult.stats || {}
        const legacyItems = Array.isArray(scanResult.items) ? scanResult.items : []
        if (!findings.length && !legacyItems.length) {
            $('.loader.rattacker').hide()
            replaceSectionFindings("dast", [])
            markSectionReady("rattacker")
            return
        }

        $('#rattacker_report').show()
        const $content = $("#rattacker_content")
        $content.html("")

        const severityLevels = ["critical", "high", "medium", "low", "info"]
        const matchesSeverity = (value, level) => String(value || "").toLowerCase() === level
        if (findings.length) {
            severityLevels.forEach(level => {
                findings
                    .filter(f => matchesSeverity(f.severity, level))
                    .forEach(finding => {
                        const legacy = mapDastFindingToLegacy(finding, vm)
                        $content.append(bindReportItem(legacy.info, legacy.original))
                    })
            })
            const exportFindings = findings.map(finding => buildExportFindingFromNormalized(finding, vm))
            replaceSectionFindings("dast", exportFindings)
        } else if (Array.isArray(scanResult.items) && scanResult.items.length) {
            severityLevels.forEach(level => {
                scanResult.items
                    .filter(item => item.attacks.some(a => a.success && matchesSeverity(a.metadata?.severity, level)))
                    .forEach(item => {
                        item.attacks.forEach(attack => {
                            if (attack.success && matchesSeverity(attack.metadata?.severity, level)) {
                                $content.append(bindReportItem(attack, item.original))
                            }
                        })
                    })
            })
            const exportFindings = []
            scanResult.items.forEach(item => {
                const original = item.original || {}
                const baseRequest = original.request || {}
                const baseResponse = original.response || {}
                item.attacks.forEach(attack => {
                    if (!attack.success) return
                    exportFindings.push({
                        engine: "DAST",
                        severity: normalizeExportSeverity(attack?.metadata?.severity || attack?.severity),
                        confidence: resolveConfidenceValue(attack?.confidence, attack?.metadata?.confidence),
                        title: attack?.metadata?.name || attack?.metadata?.id || "Finding",
                        description: attack?.metadata?.description || "",
                        location: {
                            url: baseRequest?.url || attack?.request?.url || null,
                            method: baseRequest?.method || attack?.request?.method || null,
                            param: attack?.metadata?.param || null
                        },
                        evidence: {
                            requestSnippet: truncateSnippet(attack?.request?.raw || baseRequest?.raw || ""),
                            responseSnippet: truncateSnippet(attack?.response?.raw || (attack?.response ? buildRawResponse(attack.response) : "")),
                            codeSnippet: "",
                            notes: truncateSnippet(attack?.proof || ""),
                            evidenceFullAvailable: !!(attack?.request?.raw || attack?.response?.raw || baseRequest?.raw)
                        },
                        references: buildReferenceList(attack?.metadata?.links || {}),
                        cwe: [],
                        owasp: []
                    })
                })
            })
            replaceSectionFindings("dast", exportFindings)
        } else {
            $('.loader.rattacker').hide()
            replaceSectionFindings("dast", [])
            markSectionReady("rattacker")
            return
        }

        $('#rattacker_report #attacks_count').text(stats.attacksCount ?? findings.length ?? 0)
        $('#rattacker_report #vulns_count').text(stats.findingsCount ?? findings.length ?? 0)
        $('#rattacker_report #critical_count').text(stats.critical ?? scanResult.stats?.critical ?? 0)
        $('#rattacker_report #high_count').text(stats.high ?? scanResult.stats?.high ?? 0)
        $('#rattacker_report #medium_count').text(stats.medium ?? scanResult.stats?.medium ?? 0)
        $('#rattacker_report #low_count').text(stats.low ?? scanResult.stats?.low ?? 0)
        $('#rattacker_report #info_count').text(stats.info ?? scanResult.stats?.info ?? 0)
        $('.loader.rattacker').hide()

        $(".codemirror_area").each(function (index) {
            let editor = CodeMirror.fromTextArea($(this)[0], {
                lineNumbers: false, lineWrapping: true, mode: "message/http",
                scrollbarStyle: 'native'
            })
            editor.setSize('auto', '400px')
        })
        $(".codemirror_area_html").each(function (index) {
            let editor = CodeMirror.fromTextArea($(this)[0], {
                lineNumbers: false, lineWrapping: true, mode: "text/html",
                scrollbarStyle: 'native'
            })
            editor.setSize('auto', '400px')
        })

        markSectionReady("rattacker")
        applySeverityFilter("dast")
    }


    function bindReportItem(info, original) {
        //let icon = '', proof = '', attackClass = 'nonvuln', color = ''
        let proof = '', color = ''

        let misc = rutils.getMisc(info)
        let icon = misc.icon, order = misc.order, attackClass = misc.attackClass
        const severityMeta = getSeverityMeta(info.metadata?.severity || info.severity)
        const confidence = resolveConfidenceValue(info.confidence, info.metadata?.confidence)
        const confidenceBadge = confidence !== null ? `<span class="finding-confidence" style="float: right;">Confidence: ${Math.round(confidence)}</span>` : ""

        if (info.proof)
            proof = `<div class="description"><p>Proof: <b><i name="proof">${ptk_utils.escapeHtml((info.proof))}</i></b></p></div>`
        //let headers = info.response.statusLine + '\n' + info.response.headers.map(x => x.name + ": " + x.value).join('\n')
        if (info.success) {
            color = severityMeta.color || ""
        }
        let target = original?.request?.url ? original.request.url : ""
        let request = info.request?.raw ? info.request.raw : original.request.raw
        let response = info.response?.raw
            ? info.response.raw
            : (original.response ? buildRawResponse(original.response) : '')
        const severityAttr = ptk_utils.escapeHtml(String(severityMeta.label || info.metadata?.severity || info.severity || "info").toLowerCase())
        const description = sanitizeRichText(info.metadata?.description || info.description || "")
        const recommendation = sanitizeRichText(info.metadata?.recommendation || info.recommendation || "")
        const references = renderReferenceLinks(info.metadata?.links || info.links || {})
        const mappingSection = renderMappingSection(info.metadata?.cwe || info.cwe, info.metadata?.owasp || info.owasp)
        let item = `<div class="attack_info ${attackClass} ui segment" data-severity="${severityAttr}">
                        <div class="ui ${color} message" style="margin-bottom: 0px;">
                            <div class="content">
                                <div class="header">
                                    ${icon}
                                    <a href="${target}" target="_blank">${target}</a>
                                    ${confidenceBadge}
                                </div>
                                <p>Attack: ${ptk_utils.escapeHtml(info.metadata.name)} </p>
                                ${proof}
                            </div>
                        </div>
                    <div class="two fields" >
                        <div class="one field" style="min-width: 50% !important;">
                            <textarea class="codemirror_area" style="width:100%;  border: solid 1px #cecece; padding: 1px;">${ptk_utils.escapeHtml(request)}</textarea>
                        </div>
                        <div class="one field" style="min-width: 50% !important;">
                            <textarea class="codemirror_area_html" style="width:100%;  border: solid 1px #cecece; padding: 1px;">${ptk_utils.escapeHtml(response)}</textarea>
                        </div>
                    </div>
                    ${description ? `<div class="sast-section"><div class="sast-section-title"><strong>Description</strong></div>${description}</div>` : ""}
                    ${recommendation ? `<div class="sast-section" style="margin-top: 8px;"><div class="sast-section-title"><strong>Recommendation</strong></div>${recommendation}</div>` : ""}
                    ${mappingSection}
                    ${references}
                    </div>`

        return item
    }

    const params = new URLSearchParams(window.location.search)
    const reportType = params.has('full_report')
        ? 'full'
        : (params.has('rattacker_report')
            ? 'rattacker'
            : (params.has('iast_report')
                ? 'iast'
                : (params.has('sast_report')
                    ? 'sast'
                    : (params.has('sca_report') ? 'sca' : 'full'))))
    initExportModel(reportType)

    const normalizeHost = (value) => {
        if (!value) return null
        try {
            const str = String(value).trim()
            if (!str) return null
            if (/^https?:\/\//i.test(str)) {
                return new URL(str).host
            }
            return new URL(`http://${str}`).host
        } catch (e) {
            return null
        }
    }

    const hostsMatch = (left, right) => {
        const normalizedLeft = normalizeHost(left)
        const normalizedRight = normalizeHost(right)
        if (!normalizedLeft || !normalizedRight) return true
        return normalizedLeft === normalizedRight
    }

    if (params.has('rattacker_report')) {
        $('#dashboard').hide()
        $('#rattacker_report').show()
        rattacker_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateRattacker(result)
        })
    } else if (params.has('iast_report')) {
        $('#dashboard').hide()
        $('#iast_report').show()
        iast_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateIAST(result)
        })
    } else if (params.has('sast_report')) {
        $('#dashboard').hide()
        $('#sast_report').show()
        sast_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateSAST(result)
        })
    } else if (params.has('sca_report')) {
        $('#dashboard').hide()
        $('#sca_report').show()
        sca_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateSCA(result)
        })
    } else if (params.has('full_report')) {
        index_controller.get().then(() => {
            index_controller.tab = index_controller.tab || {}
            let host = null
            $('#dashboard').show()
            browser.storage.local.get('tab_full_info').then(function (result) {
                const info = result?.tab_full_info || {}
                if (Object.prototype.hasOwnProperty.call(info, 'tabId')) {
                    index_controller.tab.tabId = info.tabId
                }
                if (Object.prototype.hasOwnProperty.call(info, 'url')) {
                    index_controller.url = info.url
                }
                if (Object.prototype.hasOwnProperty.call(info, 'technologies')) {
                    index_controller.tab.technologies = info.technologies || []
                }
                if (Object.prototype.hasOwnProperty.call(info, 'waf')) {
                    index_controller.tab.waf = info.waf || null
                }
                if (Object.prototype.hasOwnProperty.call(info, 'cves')) {
                    index_controller.tab.cves = info.cves || []
                }
                if (Object.prototype.hasOwnProperty.call(info, 'findings')) {
                    index_controller.tab.findings = info.findings || []
                }
                if (Object.prototype.hasOwnProperty.call(info, 'requestHeaders')) {
                    index_controller.tab.requestHeaders = info.requestHeaders || {}
                }
                if (Object.prototype.hasOwnProperty.call(info, 'storage')) {
                    index_controller.tab.storage = info.storage || {}
                }
                if (Object.prototype.hasOwnProperty.call(info, 'cookies')) {
                    index_controller.tab.cookies = info.cookies || {}
                }

                let host = null
                try {
                    host = index_controller.url ? new URL(index_controller.url).host : null
                } catch (_) {
                    host = null
                }
                bindInfo(host)
                bindOWASP()
                bindTechnologies()
                bindCVEs()
                bindCookies()
                bindStorage()
                bindHeaders()

                if (result?.tab_full_info) {
                    browser.storage.local.remove('tab_full_info')
                }

                rattacker_controller.init().then(function (result) {
                    if (hostsMatch(host, result?.scanResult?.host))
                        generateRattacker(result)
                })
                iast_controller.init().then(function (result) {
                    if (hostsMatch(host, result?.scanResult?.host))
                        generateIAST(result)
                })

                sast_controller.init().then(function (result) {
                    if (hostsMatch(host, result?.scanResult?.host))
                        generateSAST(result)
                })

                sca_controller.init().then(function (result) {
                    if (hostsMatch(host, result?.scanResult?.host))
                        generateSCA(result)
                })
            })
        })
    }


})
