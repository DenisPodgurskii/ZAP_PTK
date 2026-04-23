import { getGapCatalogEntry } from "../gapCatalog.js"

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function countFindingsByEngine(findings = [], engine = null) {
    if (!Array.isArray(findings) || !engine) return 0
    const upperEngine = String(engine).toUpperCase()
    return findings.reduce((sum, finding) => {
        const findingEngine = String(finding?.engine || "").toUpperCase()
        return findingEngine === upperEngine ? sum + 1 : sum
    }, 0)
}

function addGapEntry(target, code, detail, extra = {}) {
    const catalog = getGapCatalogEntry(code)
    if (!catalog) return
    target.push({
        code: catalog.code,
        severity: catalog.severity,
        engine: catalog.engine,
        recommendedActionKey: catalog.recommendedActionKey,
        detail: toNonEmptyString(detail) || catalog.defaultDetail,
        ...(extra && typeof extra === "object" ? extra : {})
    })
}

function summarizeTruncation(truncation = {}) {
    if (!truncation || typeof truncation !== "object") return null
    const entries = []
    Object.keys(truncation)
        .sort((a, b) => a.localeCompare(b))
        .forEach((key) => {
            const value = Number(truncation[key] || 0)
            if (value > 0) {
                entries.push(`${key}=${value}`)
            }
        })
    if (!entries.length) return null
    return `Analysis input caps reached (${entries.join(", ")}).`
}

function countAuthRedirects(scanResult = {}) {
    const requests = Array.isArray(scanResult.requests) ? scanResult.requests : []
    let redirects = 0
    requests.forEach((record) => {
        const targets = []
        const originalResponse = record?.original?.response
        if (originalResponse) targets.push(originalResponse)
        const attacks = Array.isArray(record?.attacks) ? record.attacks : []
        attacks.forEach((attack) => {
            if (attack?.response) targets.push(attack.response)
        })
        targets.forEach((response) => {
            const status = Number(response?.statusCode || response?.status || 0)
            if (!(status === 301 || status === 302 || status === 303 || status === 307 || status === 308)) return
            const headers = Array.isArray(response?.headers) ? response.headers : []
            const locationHeader = headers.find((header) => String(header?.name || "").toLowerCase() === "location")
            const location = String(locationHeader?.value || "").toLowerCase()
            if (!location) return
            if (location.includes("/login") || location.includes("/signin") || location.includes("/auth")) {
                redirects += 1
            }
        })
    })
    return redirects
}

function dedupeEntries(entries = []) {
    const map = new Map()
    entries.forEach((entry) => {
        if (!entry || typeof entry !== "object") return
        const key = `${entry.code || ""}|${entry.detail || ""}|${entry.engine || ""}`
        if (!map.has(key)) {
            map.set(key, entry)
        }
    })
    return Array.from(map.values())
}

export function runRuleCriticalGaps(context = {}) {
    const scanResult = context?.scanResult && typeof context.scanResult === "object" ? context.scanResult : {}
    const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
    const enginesForGapChecks = context?.enginesDataAvailableSet || context?.enginesPresentSet || new Set()
    const gaps = []
    const limitations = []

    if (enginesForGapChecks.has("DAST") || String(scanResult.engine || "").toUpperCase() === "DAST") {
        const totalPlanned = Number(scanResult?.scanStats?.totalJobsPlanned || 0)
        const totalExecuted = Number(scanResult?.scanStats?.totalJobsExecuted || 0)
        if (totalPlanned > 0) {
            const ratio = totalExecuted / totalPlanned
            if (ratio < 0.35) {
                addGapEntry(
                    limitations,
                    "DAST_LOW_CRAWL_COVERAGE",
                    `DAST executed ${totalExecuted}/${totalPlanned} planned checks (${Math.round(ratio * 100)}%).`,
                    { ratio }
                )
            }
        } else if (!Array.isArray(scanResult.requests) || scanResult.requests.length === 0) {
            addGapEntry(gaps, "DAST_LOW_CRAWL_COVERAGE", "No DAST requests were captured.")
        }
        const deferredCount = Number(scanResult?.scanStats?.skippedDueToStrategy || 0)
        if (deferredCount > 0) {
            addGapEntry(
                limitations,
                "DAST_JWT_DEFERRED_SKIPPED",
                `${deferredCount} checks were skipped by scan strategy.`,
                { count: deferredCount }
            )
        }
        const loginRedirects = countAuthRedirects(scanResult)
        if (loginRedirects >= 5) {
            addGapEntry(
                gaps,
                "DAST_AUTH_REQUIRED",
                `${loginRedirects} redirect responses pointed to login/auth routes.`,
                { count: loginRedirects }
            )
        }
    }

    if (enginesForGapChecks.has("IAST") || String(scanResult.engine || "").toUpperCase() === "IAST") {
        const runtimeEvents = Array.isArray(scanResult.runtimeEvents) ? scanResult.runtimeEvents : []
        const iastFindings = countFindingsByEngine(findings, "IAST")
        if (runtimeEvents.length === 0 && iastFindings === 0) {
            addGapEntry(gaps, "IAST_NO_RUNTIME_EVENTS", "IAST scan has no runtime events and no findings.")
        }
    }

    if (enginesForGapChecks.has("SAST") || String(scanResult.engine || "").toUpperCase() === "SAST") {
        const files = Array.isArray(scanResult.files) ? scanResult.files : []
        const sastFindings = countFindingsByEngine(findings, "SAST")
        if (files.length === 0 && sastFindings > 0) {
            addGapEntry(limitations, "SAST_NO_SOURCEMAPS", "SAST findings exist without tracked source files.")
        }
    }

    if (enginesForGapChecks.has("SCA") || String(scanResult.engine || "").toUpperCase() === "SCA") {
        const packages = Array.isArray(scanResult.packages) ? scanResult.packages : []
        const scaFindings = countFindingsByEngine(findings, "SCA")
        if (packages.length === 0 && scaFindings === 0) {
            addGapEntry(gaps, "SCA_NO_LOCKFILE_OR_PACKAGE_GRAPH", "SCA run has no package inventory and no findings.")
        }
    }

    const truncationDetail = summarizeTruncation(context?.truncation || {})
    if (truncationDetail) {
        addGapEntry(limitations, "ANALYSIS_INPUT_TRUNCATED", truncationDetail)
    }

    return {
        ruleCode: "R7_CRITICAL_GAPS",
        emits: ["coverage"],
        signals: [],
        patterns: [],
        candidateSeeds: [],
        coverage: {
            gaps: dedupeEntries(gaps),
            limitations: dedupeEntries(limitations)
        }
    }
}

export default runRuleCriticalGaps
