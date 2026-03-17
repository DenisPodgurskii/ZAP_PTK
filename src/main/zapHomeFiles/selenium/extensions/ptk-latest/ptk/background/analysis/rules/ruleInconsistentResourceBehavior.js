import { splitRouteKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const MAX_BUCKETS = 2000
const MAX_EVIDENCE_REFS = 10
const MIN_COUNT = 4

function pushEvidence(target = [], refs = []) {
    if (!Array.isArray(refs)) return
    refs.forEach((ref) => {
        if (!ref || typeof ref !== "object") return
        if (target.length >= MAX_EVIDENCE_REFS) return
        target.push(ref)
    })
}

function responseSignature(obs) {
    const statusCode = Number(obs?.statusCode || 0)
    const family = statusCode >= 500 ? "5xx"
        : statusCode >= 400 ? "4xx"
            : statusCode >= 300 ? "3xx"
                : statusCode >= 200 ? "2xx"
                    : "other"
    const body = String(obs?.responseText || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 120)
    return `${family}|${body}`
}

function scoreBucket(bucket) {
    return (bucket.statusFamilies.size * 6) + (bucket.paramKeys.size * 3) + Math.min(20, bucket.signatures.size)
}

export function runRuleInconsistentResourceBehavior(context = {}) {
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
        if (!buckets.has(routeKey)) {
            if (buckets.size >= MAX_BUCKETS) return
            buckets.set(routeKey, {
                routeKey,
                count: 0,
                paramKeys: new Set(),
                statusFamilies: new Set(),
                signatures: new Set(),
                has2xx: false,
                has4xx5xx: false,
                evidenceRefs: []
            })
        }

        const bucket = buckets.get(routeKey)
        bucket.count += 1
        const paramKey = obs.paramKey || "param:<none>"
        bucket.paramKeys.add(paramKey)

        const statusCode = Number(obs.statusCode || 0)
        const family = statusCode >= 500 ? "5xx"
            : statusCode >= 400 ? "4xx"
                : statusCode >= 300 ? "3xx"
                    : statusCode >= 200 ? "2xx"
                        : "other"
        bucket.statusFamilies.add(family)
        if (family === "2xx") bucket.has2xx = true
        if (family === "4xx" || family === "5xx") bucket.has4xx5xx = true

        bucket.signatures.add(responseSignature(obs))
        pushEvidence(bucket.evidenceRefs, obs.evidenceRefs || [])
    })

    const ranked = Array.from(buckets.values())
        .filter((bucket) => bucket.count >= MIN_COUNT)
        .filter((bucket) => bucket.paramKeys.size >= 2)
        .filter((bucket) => bucket.statusFamilies.size >= 2)
        .filter((bucket) => bucket.has2xx && bucket.has4xx5xx)
        .sort((a, b) => {
            const scoreDelta = scoreBucket(b) - scoreBucket(a)
            if (scoreDelta !== 0) return scoreDelta
            return a.routeKey.localeCompare(b.routeKey)
        })
        .slice(0, 20)

    const patterns = []
    const candidateSeeds = []
    ranked.forEach((bucket) => {
        const routeParts = splitRouteKey(bucket.routeKey)
        const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        if (!evidenceRefs.length) return

        const statusFamilies = Array.from(bucket.statusFamilies).sort((a, b) => a.localeCompare(b))
        patterns.push({
            ruleCode: "R8_INCONSISTENT_RESOURCE_BEHAVIOR",
            title: `Inconsistent resource behavior on ${routeParts.method} ${routeParts.pathTemplate}`,
            type: "RESOURCE_BEHAVIOR_DRIFT",
            routeKey: bucket.routeKey,
            paramKey: "param:<multi>",
            priority: scoreBucket(bucket),
            signals: {
                totalHits: bucket.count,
                paramFanout: bucket.paramKeys.size,
                statusFamilies,
                responseVariants: bucket.signatures.size
            },
            evidenceRefs
        })

        const signals = [
            {
                code: "RESOURCE_BEHAVIOR_DRIFT",
                value: `status=${statusFamilies.join(",")}`,
                weight: Math.min(20, 8 + bucket.statusFamilies.size + bucket.paramKeys.size)
            },
            {
                code: "PARAM_FANOUT",
                value: bucket.paramKeys.size,
                weight: Math.min(14, 4 + (bucket.paramKeys.size * 2))
            }
        ]
        if (bucket.statusFamilies.has("5xx")) {
            signals.push({
                code: "REPEATED_5XX",
                value: bucket.count,
                weight: 16
            })
        }

        candidateSeeds.push({
            createdByRule: "R8_INCONSISTENT_RESOURCE_BEHAVIOR",
            type: "AUTHZ_INCONSISTENCY",
            title: `Resource behavior drift on ${routeParts.method} ${routeParts.pathTemplate}`,
            routeKey: bucket.routeKey,
            paramKey: "param:<multi>",
            engineSignals: ["DAST"],
            repeatabilityCount: bucket.count,
            signals,
            evidenceRefs,
            manualSteps: [
                "Replay the same route with equivalent payload shapes and compare status/body consistency.",
                "Compare responses across user roles and authentication states for the same route family.",
                "Validate cache/proxy behavior to rule out route fallback or catch-all response masking."
            ]
        })
    })

    return {
        ruleCode: "R8_INCONSISTENT_RESOURCE_BEHAVIOR",
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds
    }
}

export default runRuleInconsistentResourceBehavior
