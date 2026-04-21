import { normalizeEngineName } from "./canonicalize.js"
import { deriveRouteEnginesByFamily } from "./scanAnalysisEngine.js"

const ENGINE_ORDER = Object.freeze(["DAST", "IAST", "SAST", "SCA"])

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value))
}

function sortEngines(engines = []) {
    const deduped = Array.from(new Set((Array.isArray(engines) ? engines : []).filter(Boolean)))
    return deduped.sort((a, b) => {
        const aIdx = ENGINE_ORDER.indexOf(a)
        const bIdx = ENGINE_ORDER.indexOf(b)
        if (aIdx >= 0 && bIdx >= 0) return aIdx - bIdx
        if (aIdx >= 0) return -1
        if (bIdx >= 0) return 1
        return String(a).localeCompare(String(b))
    })
}

function deepClone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function normalizeCoverageEntries(entries = []) {
    return Array.isArray(entries)
        ? entries.filter((entry) => entry && typeof entry === "object").map((entry) => ({ ...entry }))
        : []
}

function hasSastArtifacts(scan = {}) {
    const sast = scan?.codeArtifacts?.sast
    return Boolean(
        Array.isArray(sast?.routes) && sast.routes.length
        || Array.isArray(sast?.endpoints) && sast.endpoints.length
        || Array.isArray(sast?.graphql) && sast.graphql.length
        || Array.isArray(sast?.surfaces) && sast.surfaces.length
        || Array.isArray(sast?.hiddenParams) && sast.hiddenParams.length
        || Array.isArray(sast?.gadgets) && sast.gadgets.length
    )
}

function scanHasSignals(scan = {}) {
    return Boolean(
        (Array.isArray(scan?.findings) && scan.findings.length > 0)
        || (Array.isArray(scan?.requests) && scan.requests.length > 0)
        || (Array.isArray(scan?.runtimeEvents) && scan.runtimeEvents.length > 0)
        || (Array.isArray(scan?.files) && scan.files.length > 0)
        || hasSastArtifacts(scan)
        || Number(scan?.stats?.findingsCount || 0) > 0
        || Number(scan?.stats?.attacksCount || 0) > 0
        || Number(scan?.scanStats?.totalJobsExecuted || 0) > 0
    )
}

function collectEnginesPresent(primaryScan, relatedScans = []) {
    const scans = [primaryScan, ...(Array.isArray(relatedScans) ? relatedScans : [])]
    const engines = new Set()
    scans.forEach((scan) => {
        if (!scan || typeof scan !== "object") return
        if (!scanHasSignals(scan)) return
        const engine = normalizeEngineName(scan?.engine)
        if (engine) engines.add(engine)
    })
    return sortEngines(Array.from(engines))
}

function mergeRouteFamilyMaps(scans = []) {
    const merged = new Map()
    ;(Array.isArray(scans) ? scans : []).forEach((scan) => {
        if (!scan || typeof scan !== "object") return
        const familyMap = deriveRouteEnginesByFamily(scan)
        familyMap.forEach((engines, family) => {
            if (!merged.has(family)) {
                merged.set(family, new Set())
            }
            const target = merged.get(family)
            ;(engines instanceof Set ? Array.from(engines) : Array.isArray(engines) ? engines : []).forEach((engine) => {
                const normalized = normalizeEngineName(engine)
                if (normalized) target.add(normalized)
            })
        })
    })
    return merged
}

function deriveRouteAwareCoverage(primaryScan, relatedScans = [], hostLevelEngines = []) {
    const allScans = [primaryScan, ...(Array.isArray(relatedScans) ? relatedScans : [])]
    const mergedRouteFamilies = mergeRouteFamilyMaps(allScans)
    const primaryRouteMap = deriveRouteEnginesByFamily(primaryScan || {})
    const primaryFamilies = Array.from(primaryRouteMap.keys())
    const routeAwareEngines = new Set()
    const ROUTE_SCOPED_ENGINES = new Set(["DAST", "IAST"])

    if (!primaryFamilies.length) {
        return {
            enginesRouteOverlap: sortEngines(hostLevelEngines.filter((engine) => ROUTE_SCOPED_ENGINES.has(engine))),
            enginesHostOnly: [],
            routeFamilies: [],
            routeFamilyCount: 0
        }
    }

    primaryFamilies.forEach((family) => {
        const engines = mergedRouteFamilies.get(family)
        if (!engines) return
        engines.forEach((engine) => routeAwareEngines.add(engine))
    })

    ;(Array.isArray(relatedScans) ? relatedScans : []).forEach((scan) => {
        const engine = normalizeEngineName(scan?.engine)
        if (!engine) return
        const familyMap = deriveRouteEnginesByFamily(scan || {})
        if (ROUTE_SCOPED_ENGINES.has(engine) && !familyMap.size && scanHasSignals(scan)) {
            routeAwareEngines.add(engine)
        }
    })

    const routeFamilies = primaryFamilies.map((family) => ({
        routeFamily: family,
        enginesPresent: sortEngines(Array.from(mergedRouteFamilies.get(family) || []))
    }))

    const enginesRouteOverlap = sortEngines(Array.from(routeAwareEngines))
    const hostOnlyCandidates = Array.isArray(hostLevelEngines) ? hostLevelEngines : []
    const enginesHostOnly = sortEngines(hostOnlyCandidates.filter((engine) => !enginesRouteOverlap.includes(engine)))

    return {
        enginesRouteOverlap,
        enginesHostOnly,
        routeFamilies,
        routeFamilyCount: routeFamilies.length
    }
}

function computeMergedCoverageConfidence({ primaryScan, enginesPresent, gaps, limitations, relatedScans = [] }) {
    const severityPenaltyGap = { high: 20, med: 10, low: 5 }
    const severityPenaltyLimitation = { high: 10, med: 5, low: 2 }
    let score = 20 + (enginesPresent.length * 15)

    const totalPlanned = Number(primaryScan?.scanStats?.totalJobsPlanned || 0)
    const totalExecuted = Number(primaryScan?.scanStats?.totalJobsExecuted || 0)
    if (totalPlanned > 0) {
        const ratio = totalExecuted / totalPlanned
        if (ratio >= 0.7) score += 10
        if (ratio < 0.4) score -= 10
    }

    const hasRuntimeSignals = [primaryScan, ...(Array.isArray(relatedScans) ? relatedScans : [])]
        .some((scan) => Array.isArray(scan?.runtimeEvents) && scan.runtimeEvents.length > 0)
    if (hasRuntimeSignals) score += 5

    gaps.forEach((gap) => {
        const sev = String(gap?.severity || "low").toLowerCase()
        score -= severityPenaltyGap[sev] || 5
    })
    limitations.forEach((limitation) => {
        const sev = String(limitation?.severity || "low").toLowerCase()
        score -= severityPenaltyLimitation[sev] || 2
    })

    score = clamp(Math.round(score), 0, 100)
    return {
        confidence: score >= 75 ? "high" : score >= 45 ? "medium" : "low",
        confidenceScore: score
    }
}

export function buildHostCoverageAnalysis({
    primaryScan = null,
    primaryCoverage = null,
    relatedScans = [],
    windowMs = null
} = {}) {
    const coverage = primaryCoverage && typeof primaryCoverage === "object"
        ? deepClone(primaryCoverage)
        : {}
    coverage.gaps = normalizeCoverageEntries(coverage.gaps || [])
    coverage.limitations = normalizeCoverageEntries(coverage.limitations || [])

    const related = Array.isArray(relatedScans) ? relatedScans.filter((scan) => scan && typeof scan === "object") : []
    const hostLevelEngines = collectEnginesPresent(primaryScan, related)
    const routeAwareCoverage = deriveRouteAwareCoverage(primaryScan, related, hostLevelEngines)

    coverage.enginesPresent = hostLevelEngines
    coverage.enginesMissing = sortEngines(ENGINE_ORDER.filter((engine) => !hostLevelEngines.includes(engine)))
    coverage.enginesRouteOverlap = routeAwareCoverage.enginesRouteOverlap
    coverage.enginesHostOnly = routeAwareCoverage.enginesHostOnly
    coverage.routeFamilies = routeAwareCoverage.routeFamilies
    coverage.routeFamilyCount = routeAwareCoverage.routeFamilyCount
    coverage.scope = "host_session"
    coverage.relatedScansCount = related.length
    coverage.windowMs = Number(windowMs || 0) > 0 ? Number(windowMs) : null

    if (coverage.enginesHostOnly.length > 0) {
        coverage.limitations.push({
            code: "ENGINE_HOST_ONLY_PRESENCE",
            severity: "low",
            engine: "ANALYSIS",
            recommendedActionKey: "ACTION_EXPAND_ROUTE_EXPLORATION",
            detail: `${coverage.enginesHostOnly.join(", ")} evidence exists on the same host/session but not on overlapping DAST route families.`
        })
    }

    const confidence = computeMergedCoverageConfidence({
        primaryScan,
        enginesPresent: coverage.enginesPresent,
        gaps: coverage.gaps,
        limitations: coverage.limitations,
        relatedScans: related
    })
    coverage.confidence = confidence.confidence
    coverage.confidenceScore = confidence.confidenceScore

    return coverage
}

export default buildHostCoverageAnalysis
