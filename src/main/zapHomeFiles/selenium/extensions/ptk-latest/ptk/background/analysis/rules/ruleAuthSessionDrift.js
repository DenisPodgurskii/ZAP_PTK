import { splitRouteKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const AUTH_HINT_RE = /\b(login|signin|auth|session|token|forbidden|unauthori[sz]ed)\b/i
const MAX_ROUTE_BUCKETS = 2000
const MAX_EVIDENCE_REFS = 10
const MIN_BUCKET_COUNT = 3

function pushEvidence(target = [], refs = []) {
    if (!Array.isArray(refs)) return
    refs.forEach((ref) => {
        if (!ref || typeof ref !== "object") return
        if (target.length >= MAX_EVIDENCE_REFS) return
        target.push(ref)
    })
}

function statusFamily(statusCode) {
    const code = Number(statusCode || 0)
    if (!Number.isFinite(code) || code <= 0) return "unknown"
    if (code >= 500) return "5xx"
    if (code >= 400) return "4xx"
    if (code >= 300) return "3xx"
    if (code >= 200) return "2xx"
    if (code >= 100) return "1xx"
    return "unknown"
}

function scoreBucket(bucket) {
    return (bucket.authSignalCount * 5) + (bucket.successCount * 2) + bucket.statusFamilies.size
}

export function runRuleAuthSessionDrift(context = {}) {
    const observations = (
        Array.isArray(context.analysisObservations) && context.analysisObservations.length
            ? context.analysisObservations
            : (Array.isArray(context.attackObservations) ? context.attackObservations : [])
    )
    const buckets = new Map()
    const sorted = observations
        .slice()
        .sort((a, b) => {
            const aKey = `${a.routeKey || ""}|${a.paramKey || ""}|${a.attackId || ""}`
            const bKey = `${b.routeKey || ""}|${b.paramKey || ""}|${b.attackId || ""}`
            return aKey.localeCompare(bKey)
        })

    sorted.forEach((obs) => {
        const routeKey = obs.routeKey || "unknown-host|GET|/"
        const paramKey = obs.paramKey || "param:<none>"
        const key = `${routeKey}|${paramKey}`
        if (!buckets.has(key)) {
            if (buckets.size >= MAX_ROUTE_BUCKETS) return
            buckets.set(key, {
                routeKey,
                paramKey,
                count: 0,
                successCount: 0,
                unauthorizedCount: 0,
                authHintCount: 0,
                statusFamilies: new Set(),
                evidenceRefs: []
            })
        }

        const bucket = buckets.get(key)
        bucket.count += 1

        const status = Number(obs.statusCode || 0)
        const family = statusFamily(status)
        bucket.statusFamilies.add(family)

        if (status >= 200 && status <= 299) {
            bucket.successCount += 1
        }

        const responseText = String(obs.responseText || "")
        const unauthorized = status === 401 || status === 403
        const authHint = unauthorized || AUTH_HINT_RE.test(responseText)
        if (unauthorized) {
            bucket.unauthorizedCount += 1
        }
        if (authHint) {
            bucket.authHintCount += 1
        }

        pushEvidence(bucket.evidenceRefs, obs.evidenceRefs || [])
    })

    const ranked = Array.from(buckets.values())
        .filter((bucket) => bucket.count >= MIN_BUCKET_COUNT)
        .filter((bucket) => bucket.successCount > 0)
        .filter((bucket) => bucket.authHintCount > 0)
        .sort((a, b) => {
            const scoreDelta = scoreBucket(b) - scoreBucket(a)
            if (scoreDelta !== 0) return scoreDelta
            return `${a.routeKey}|${a.paramKey}`.localeCompare(`${b.routeKey}|${b.paramKey}`)
        })
        .slice(0, 20)

    const patterns = []
    const candidateSeeds = []

    ranked.forEach((bucket) => {
        const routeParts = splitRouteKey(bucket.routeKey)
        const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        if (!evidenceRefs.length) return

        patterns.push({
            ruleCode: "R3_AUTH_SESSION_DRIFT",
            title: `Auth/session drift on ${routeParts.method} ${routeParts.pathTemplate}`,
            type: "AUTH_SESSION_DRIFT",
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            priority: scoreBucket(bucket),
            signals: {
                totalHits: bucket.count,
                successCount: bucket.successCount,
                authSignalCount: bucket.authHintCount,
                statusFamilies: Array.from(bucket.statusFamilies).sort((a, b) => a.localeCompare(b))
            },
            evidenceRefs
        })

        const signals = [
            {
                code: "AUTH_SESSION_SIGNAL",
                value: `auth=${bucket.authHintCount},ok=${bucket.successCount}`,
                weight: Math.min(20, 8 + (bucket.authHintCount * 2))
            }
        ]
        if (bucket.unauthorizedCount > 0) {
            signals.push({
                code: "PARAM_FANOUT",
                value: bucket.statusFamilies.size,
                weight: Math.min(12, 4 + bucket.statusFamilies.size)
            })
        }

        candidateSeeds.push({
            createdByRule: "R3_AUTH_SESSION_DRIFT",
            type: "AUTHZ_INCONSISTENCY",
            title: `Auth/session inconsistency on ${routeParts.method} ${routeParts.pathTemplate}`,
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            engineSignals: ["DAST"],
            repeatabilityCount: bucket.authHintCount,
            signals,
            evidenceRefs,
            manualSteps: [
                "Replay the same request as anonymous and authenticated users and compare status/body deltas.",
                "Rotate session cookies/tokens (valid, expired, malformed) and verify authorization checks stay consistent.",
                "Check role boundaries on equivalent routes to confirm no privilege bypass path exists."
            ]
        })
    })

    return {
        ruleCode: "R3_AUTH_SESSION_DRIFT",
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds
    }
}

export default runRuleAuthSessionDrift
