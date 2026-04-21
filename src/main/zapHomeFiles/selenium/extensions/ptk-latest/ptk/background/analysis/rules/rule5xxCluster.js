import { splitRouteKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const MIN_CLUSTER_SIZE = 3
const MAX_EVIDENCE_REFS = 10
const MAX_ROUTE_BUCKETS = 2000

function pushEvidence(target = [], refs = []) {
    if (!Array.isArray(refs) || !refs.length) return
    refs.forEach((ref) => {
        if (!ref || typeof ref !== "object") return
        if (target.length >= MAX_EVIDENCE_REFS) return
        target.push(ref)
    })
}

export function runRule5xxCluster(context = {}) {
    const observations = (
        Array.isArray(context.analysisObservations) && context.analysisObservations.length
            ? context.analysisObservations
            : (Array.isArray(context.attackObservations) ? context.attackObservations : [])
    )
    const buckets = new Map()
    const sortedObservations = observations
        .slice()
        .sort((a, b) => {
            const aKey = `${a.routeKey || ""}|${a.paramKey || ""}|${a.attackId || ""}`
            const bKey = `${b.routeKey || ""}|${b.paramKey || ""}|${b.attackId || ""}`
            return aKey.localeCompare(bKey)
        })

    sortedObservations.forEach((obs) => {
        const status = Number(obs.statusCode || 0)
        if (!Number.isFinite(status) || status < 500 || status > 599) return
        const routeKey = obs.routeKey || "unknown-host|GET|/"
        const paramKey = obs.paramKey || "param:<none>"
        const key = `${routeKey}|${paramKey}`
        if (!buckets.has(key)) {
            if (buckets.size >= MAX_ROUTE_BUCKETS) return
            buckets.set(key, {
                routeKey,
                paramKey,
                count: 0,
                families: new Set(),
                evidenceRefs: []
            })
        }
        const bucket = buckets.get(key)
        bucket.count += 1
        const family = obs.ruleId || obs.moduleId || obs.category || "unknown"
        bucket.families.add(String(family))
        pushEvidence(bucket.evidenceRefs, obs.evidenceRefs || [])
    })

    const patterns = []
    const candidateSeeds = []
    Array.from(buckets.values())
        .sort((a, b) => {
            if (b.count !== a.count) return b.count - a.count
            return `${a.routeKey}|${a.paramKey}`.localeCompare(`${b.routeKey}|${b.paramKey}`)
        })
        .forEach((bucket) => {
            if (bucket.count < MIN_CLUSTER_SIZE) return
            const routeParts = splitRouteKey(bucket.routeKey)
            const familyCount = bucket.families.size
            const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
            patterns.push({
                ruleCode: "R1_5XX_CLUSTER",
                title: `5xx burst on ${routeParts.method} ${routeParts.pathTemplate} (${bucket.paramKey.replace(/^param:/, "")})`,
                type: "ERROR_CLUSTER",
                routeKey: bucket.routeKey,
                paramKey: bucket.paramKey,
                priority: bucket.count,
                signals: {
                    count5xx: bucket.count,
                    uniqueAttackFamilies: familyCount
                },
                evidenceRefs
            })
            candidateSeeds.push({
                createdByRule: "R1_5XX_CLUSTER",
                type: "RUNTIME_ANOMALY",
                title: `Unhandled error cluster on ${routeParts.method} ${routeParts.pathTemplate}`,
                routeKey: bucket.routeKey,
                paramKey: bucket.paramKey,
                engineSignals: ["DAST"],
                repeatabilityCount: bucket.count,
                signals: [
                    { code: "REPEATED_5XX", value: bucket.count },
                    { code: "PARAM_FANOUT", value: familyCount, weight: Math.min(12, familyCount * 2) }
                ],
                evidenceRefs,
                manualSteps: [
                    `Replay the failing request for ${bucket.paramKey.replace(/^param:/, "")} with boundary values and type variants.`,
                    "Switch payload encoding (raw, URL-encoded, JSON string) and compare status/body deltas.",
                    "Correlate returned error ids with server logs to locate failing handler path."
                ]
            })
        })

    return {
        ruleCode: "R1_5XX_CLUSTER",
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds
    }
}

export default runRule5xxCluster
