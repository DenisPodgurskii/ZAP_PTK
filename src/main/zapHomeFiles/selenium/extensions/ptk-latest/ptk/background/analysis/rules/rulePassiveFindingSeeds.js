import { buildRouteKey, normalizeEngineName, normalizeParamKey, splitRouteKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const MAX_CANDIDATES = 25
const MAX_EVIDENCE_REFS = 10
const SEVERITY_WEIGHT = Object.freeze({
    critical: 26,
    high: 20,
    medium: 14,
    low: 8,
    info: 4
})
const SEVERITY_RANK = Object.freeze({
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
})
const AUTH_HINT_RE = /(?:^|[^a-z0-9])(auth|session|token|jwt|login|access|role|admin|privilege|idor|bola|csrf|oauth|sso)(?:$|[^a-z0-9])/i

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function parseQueryParams(url, hostHint = null) {
    const raw = toNonEmptyString(url)
    if (!raw) return []
    try {
        const base = hostHint ? `http://${String(hostHint).trim()}` : "http://localhost"
        const parsed = new URL(raw, base)
        const names = new Set()
        for (const key of parsed.searchParams.keys()) {
            const trimmed = toNonEmptyString(key)
            if (trimmed) names.add(trimmed)
        }
        return Array.from(names).sort((a, b) => a.localeCompare(b))
    } catch (_) {
        return []
    }
}

function addSignal(signals, code, value, weight = null) {
    const signal = { code, value }
    if (Number.isFinite(Number(weight))) {
        signal.weight = Number(weight)
    }
    signals.push(signal)
}

function buildEvidenceRefs(finding = {}, routeKey = "unknown-host|GET|/") {
    const requestId = toNonEmptyString(finding?.evidence?.dast?.requestId)
    const attackId = toNonEmptyString(finding?.evidence?.dast?.attackId)
    const findingId = toNonEmptyString(finding?.id)
    const method = toNonEmptyString(finding?.location?.method) || "GET"
    const path = String(routeKey).split("|")[2] || "/"
    return normalizeEvidenceRefs([
        findingId ? {
            type: "finding",
            id: findingId,
            loc: {
                module: finding?.moduleId || null,
                rule: finding?.ruleId || null,
                severity: finding?.severity || null
            }
        } : null,
        requestId ? {
            type: "request",
            id: requestId,
            loc: { method, path }
        } : null,
        attackId ? {
            type: "attack",
            id: attackId,
            loc: {
                module: finding?.moduleId || null,
                rule: finding?.ruleId || null,
                method
            }
        } : null
    ], { maxRefs: MAX_EVIDENCE_REFS })
}

function isAuthLikeFinding(finding = {}) {
    const blob = [
        finding?.moduleId,
        finding?.ruleId,
        finding?.category,
        finding?.vulnId,
        finding?.title,
        finding?.name
    ]
        .map((value) => String(value || ""))
        .join(" ")
    return AUTH_HINT_RE.test(blob)
}

function scoreBucket(bucket = {}) {
    const severityWeight = Number(SEVERITY_WEIGHT[String(bucket.severity || "low").toLowerCase()] || 8)
    const count = Number(bucket.count || 0)
    const authBonus = bucket.authLike ? 8 : 0
    return severityWeight + Math.min(20, count * 3) + authBonus
}

function isSeverityHigher(nextSeverity, currentSeverity) {
    const next = Number(SEVERITY_RANK[String(nextSeverity || "low").toLowerCase()] || 0)
    const current = Number(SEVERITY_RANK[String(currentSeverity || "low").toLowerCase()] || 0)
    return next > current
}

export function runRulePassiveFindingSeeds(context = {}) {
    const attackObservations = Array.isArray(context.attackObservations) ? context.attackObservations : []
    if (attackObservations.length > 0) {
        return {
            ruleCode: "R9_PASSIVE_FINDING_SEEDS",
            emits: ["pattern", "candidates"],
            signals: [],
            patterns: [],
            candidateSeeds: []
        }
    }

    const scanResult = context?.scanResult && typeof context.scanResult === "object" ? context.scanResult : {}
    const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
    const hostHint = toNonEmptyString(scanResult?.host)
    const buckets = new Map()

    findings.forEach((finding) => {
        if (!finding || typeof finding !== "object") return
        const engine = normalizeEngineName(finding?.engine || scanResult?.engine || "DAST")
        if (engine !== "DAST") return
        const location = finding?.location || {}
        const url = location?.runtimeUrl || location?.url || location?.route || null
        const method = toNonEmptyString(location?.method) || "GET"
        const routeKey = buildRouteKey({
            url,
            method,
            host: hostHint
        })
        const directParam = toNonEmptyString(location?.param)
        const params = directParam ? [directParam] : parseQueryParams(url, hostHint)
        const paramNames = params.length ? params : ["<none>"]
        const severity = String(finding?.severity || "low").toLowerCase()
        const authLike = isAuthLikeFinding(finding)
        const moduleRule = `${finding?.moduleId || "module_unknown"}:${finding?.ruleId || "rule_unknown"}`

        paramNames.forEach((rawParam) => {
            const paramKey = normalizeParamKey(rawParam, "param")
            const key = `${routeKey}|${paramKey}|${moduleRule}`
            if (!buckets.has(key)) {
                buckets.set(key, {
                    routeKey,
                    paramKey,
                    moduleRule,
                    severity,
                    authLike,
                    count: 0,
                    evidenceRefs: []
                })
            }
            const bucket = buckets.get(key)
            bucket.count += 1
            if (isSeverityHigher(severity, bucket.severity)) {
                bucket.severity = severity
            }
            if (authLike) bucket.authLike = true
            const refs = buildEvidenceRefs(finding, routeKey)
            refs.forEach((ref) => {
                if (bucket.evidenceRefs.length >= MAX_EVIDENCE_REFS) return
                bucket.evidenceRefs.push(ref)
            })
        })
    })

    const ranked = Array.from(buckets.values())
        .filter((bucket) => Array.isArray(bucket.evidenceRefs) && bucket.evidenceRefs.length > 0)
        .sort((a, b) => {
            const scoreDelta = scoreBucket(b) - scoreBucket(a)
            if (scoreDelta !== 0) return scoreDelta
            return `${a.routeKey}|${a.paramKey}|${a.moduleRule}`.localeCompare(`${b.routeKey}|${b.paramKey}|${b.moduleRule}`)
        })
        .slice(0, MAX_CANDIDATES)

    const patterns = []
    const candidateSeeds = []
    ranked.forEach((bucket) => {
        const routeParts = splitRouteKey(bucket.routeKey)
        const priority = scoreBucket(bucket)
        const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        patterns.push({
            ruleCode: "R9_PASSIVE_FINDING_SEEDS",
            title: `Passive finding seed on ${routeParts.method} ${routeParts.pathTemplate}`,
            type: "PASSIVE_FINDING_CLUSTER",
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            priority,
            signals: {
                source: "passive_findings",
                moduleRule: bucket.moduleRule,
                hits: bucket.count,
                severity: bucket.severity
            },
            evidenceRefs
        })

        const signals = []
        addSignal(signals, "PASSIVE_FINDING_SEED", bucket.moduleRule, SEVERITY_WEIGHT[bucket.severity] || 8)
        if (bucket.count > 1) {
            addSignal(signals, "PARAM_HOTSPOT", bucket.count, Math.min(12, 4 + (bucket.count * 2)))
        }
        if (bucket.authLike) {
            addSignal(signals, "AUTH_SESSION_SIGNAL", "passive_auth_pattern", 12)
        }

        candidateSeeds.push({
            createdByRule: "R9_PASSIVE_FINDING_SEEDS",
            type: bucket.authLike ? "AUTHZ_INCONSISTENCY" : "RUNTIME_ANOMALY",
            title: `Promote passive finding to active validation on ${routeParts.method} ${routeParts.pathTemplate}`,
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            engineSignals: ["DAST"],
            repeatabilityCount: bucket.count,
            signals,
            evidenceRefs,
            manualSteps: [
                "Replay the passive finding request as baseline and preserve captured headers/cookies.",
                "Run targeted active mutations only on this route/parameter pair with incremental payload strength.",
                "Compare baseline vs mutated responses to confirm exploitability before broad active coverage."
            ]
        })
    })

    return {
        ruleCode: "R9_PASSIVE_FINDING_SEEDS",
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds
    }
}

export default runRulePassiveFindingSeeds
