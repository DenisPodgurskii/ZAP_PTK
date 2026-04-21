import { splitRouteKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const MAX_BUCKETS = 2000
const MAX_EVIDENCE_REFS = 10
const MIN_COUNT = 4
const MIN_OUTLIER_MS = 1500

function pushEvidence(target = [], refs = []) {
    if (!Array.isArray(refs)) return
    refs.forEach((ref) => {
        if (!ref || typeof ref !== "object") return
        if (target.length >= MAX_EVIDENCE_REFS) return
        target.push(ref)
    })
}

function quantile(sorted = [], q = 0.5) {
    if (!Array.isArray(sorted) || sorted.length === 0) return 0
    if (sorted.length === 1) return Number(sorted[0] || 0)
    const clamped = Math.max(0, Math.min(1, Number(q) || 0))
    const pos = (sorted.length - 1) * clamped
    const lower = Math.floor(pos)
    const upper = Math.ceil(pos)
    if (lower === upper) return Number(sorted[lower] || 0)
    const weight = pos - lower
    const low = Number(sorted[lower] || 0)
    const high = Number(sorted[upper] || 0)
    return low + ((high - low) * weight)
}

function scoreBucket(bucket, baseline, p90, outlierCount) {
    return Math.round((outlierCount * 4) + Math.min(20, p90 / 400) + Math.min(10, baseline / 600) + (bucket.count / 2))
}

export function runRuleLatencyOutliers(context = {}) {
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
        const timeMs = Number(obs.timeMs || 0)
        if (!Number.isFinite(timeMs) || timeMs <= 0) return

        const routeKey = obs.routeKey || "unknown-host|GET|/"
        const paramKey = obs.paramKey || "param:<none>"
        const key = `${routeKey}|${paramKey}`
        if (!buckets.has(key)) {
            if (buckets.size >= MAX_BUCKETS) return
            buckets.set(key, {
                routeKey,
                paramKey,
                count: 0,
                times: [],
                evidenceRefs: []
            })
        }

        const bucket = buckets.get(key)
        bucket.count += 1
        bucket.times.push(timeMs)
        pushEvidence(bucket.evidenceRefs, obs.evidenceRefs || [])
    })

    const ranked = []
    Array.from(buckets.values()).forEach((bucket) => {
        if (bucket.count < MIN_COUNT || bucket.times.length < MIN_COUNT) return
        const times = bucket.times
            .slice()
            .sort((a, b) => a - b)
        const median = quantile(times, 0.5)
        const baseline = Math.max(1, quantile(times, 0.25))
        const p90 = quantile(times, 0.9)
        const dynamicCutoff = Math.max(MIN_OUTLIER_MS, Math.round(baseline * 2))
        const outlierCount = times.filter((t) => t >= dynamicCutoff).length
        const ratio = baseline > 0 ? (p90 / baseline) : 0
        if (outlierCount < 2) return
        if (ratio < 2.0 && p90 < 3000) return

        ranked.push({
            ...bucket,
            baseline,
            median,
            p90,
            outlierCount,
            score: scoreBucket(bucket, baseline, p90, outlierCount)
        })
    })

    ranked.sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score
        return `${a.routeKey}|${a.paramKey}`.localeCompare(`${b.routeKey}|${b.paramKey}`)
    })

    const patterns = []
    const candidateSeeds = []
    ranked.slice(0, 20).forEach((bucket) => {
        const routeParts = splitRouteKey(bucket.routeKey)
        const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        if (!evidenceRefs.length) return

        patterns.push({
            ruleCode: "R5_LATENCY_OUTLIERS",
            title: `Latency outliers on ${routeParts.method} ${routeParts.pathTemplate}`,
            type: "LATENCY_OUTLIER_CLUSTER",
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            priority: bucket.score,
            signals: {
                totalHits: bucket.count,
                baselineMs: Math.round(bucket.baseline),
                medianMs: Math.round(bucket.median),
                p90Ms: Math.round(bucket.p90),
                outlierCount: bucket.outlierCount
            },
            evidenceRefs
        })

        const signals = [
            {
                code: "LATENCY_OUTLIER",
                value: `p90=${Math.round(bucket.p90)},baseline=${Math.round(bucket.baseline)}`,
                weight: Math.min(24, 10 + (bucket.outlierCount * 2))
            }
        ]
        if (bucket.outlierCount >= 4) {
            signals.push({
                code: "PARAM_HOTSPOT",
                value: bucket.outlierCount,
                weight: 12
            })
        }

        candidateSeeds.push({
            createdByRule: "R5_LATENCY_OUTLIERS",
            type: "RUNTIME_ANOMALY",
            title: `Latency anomaly candidate on ${routeParts.method} ${routeParts.pathTemplate}`,
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            engineSignals: ["DAST"],
            repeatabilityCount: bucket.outlierCount,
            signals,
            evidenceRefs,
            manualSteps: [
                "Replay baseline and mutated requests in R-Builder and compare latency percentiles.",
                "Test payload size, nested JSON depth, and encoding variants to isolate expensive execution paths.",
                "Correlate slow responses with server traces/logs to confirm lock contention or heavy query plans."
            ]
        })
    })

    return {
        ruleCode: "R5_LATENCY_OUTLIERS",
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds
    }
}

export default runRuleLatencyOutliers
