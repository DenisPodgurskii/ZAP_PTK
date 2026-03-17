import { splitRouteKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const SLOW_REQUEST_MS = 3000
const MAX_PARAM_BUCKETS = 5000
const MAX_EVIDENCE_REFS = 10
const MAX_CANDIDATES = 20
const MIN_TOP_ROUTE_HITS = 2
const LOW_VALUE_PARAM_NAMES = new Set([
    "host",
    "origin",
    "referer",
    "referrer",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "connection",
    "content-length",
    "content-type",
    "cache-control",
    "pragma",
    "upgrade-insecure-requests",
    "dnt",
    "te",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded"
])

function pushEvidence(target = [], refs = []) {
    if (!Array.isArray(refs)) return
    refs.forEach((ref) => {
        if (!ref || typeof ref !== "object") return
        if (target.length >= MAX_EVIDENCE_REFS) return
        target.push(ref)
    })
}

function scoreBucket(bucket) {
    return (bucket.anomalyCount * 3) + bucket.count + Math.min(bucket.routeCounts.size, 10)
}

function normalizeParamName(paramKey) {
    const raw = String(paramKey || "")
    const parts = raw.split(":")
    const name = parts.length > 1 ? parts.slice(1).join(":") : raw
    return name.trim().toLowerCase()
}

function isLowValueParam(paramKey) {
    const name = normalizeParamName(paramKey)
    if (!name) return true
    if (LOW_VALUE_PARAM_NAMES.has(name)) return true
    if (name.startsWith("sec-")) return true
    if (name.startsWith("if-")) return true
    if (name.startsWith("x-forwarded-")) return true
    return false
}

function normalizeResponseFingerprintText(value) {
    return String(value || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 180)
}

function buildResponseFingerprint(obs) {
    const status = Number(obs?.statusCode || 0)
    const body = normalizeResponseFingerprintText(obs?.responseText || "")
    return `${status}|${body}`
}

function dominantFingerprint(stats) {
    if (!stats || !(stats.fingerprints instanceof Map) || stats.fingerprints.size === 0) return null
    const ranked = Array.from(stats.fingerprints.entries())
        .sort((a, b) => {
            if (b[1] !== a[1]) return b[1] - a[1]
            return a[0].localeCompare(b[0])
        })
    return ranked[0]?.[0] || null
}

function isLikelyCatchAllRoute(routeKey, routeStatsByKey) {
    const routeParts = splitRouteKey(routeKey)
    if (routeParts.pathTemplate === "/") return false
    const routeStats = routeStatsByKey.get(routeKey)
    if (!routeStats || routeStats.count < MIN_TOP_ROUTE_HITS) return false
    const successRatio = routeStats.count > 0 ? (routeStats.success2xx / routeStats.count) : 0
    if (successRatio < 0.85) return false
    const rootKey = `${routeParts.host}|${routeParts.method}|/`
    const rootStats = routeStatsByKey.get(rootKey)
    if (!rootStats || rootStats.count < MIN_TOP_ROUTE_HITS) return false
    const routeFingerprint = dominantFingerprint(routeStats)
    const rootFingerprint = dominantFingerprint(rootStats)
    if (!routeFingerprint || !rootFingerprint) return false
    return routeFingerprint === rootFingerprint
}

export function runRuleParamHotspot(context = {}) {
    const observations = (
        Array.isArray(context.analysisObservations) && context.analysisObservations.length
            ? context.analysisObservations
            : (Array.isArray(context.attackObservations) ? context.attackObservations : [])
    )
    const buckets = new Map()
    const routeStatsByKey = new Map()
    const sorted = observations
        .slice()
        .sort((a, b) => {
            const aKey = `${a.paramKey || ""}|${a.routeKey || ""}|${a.attackId || ""}`
            const bKey = `${b.paramKey || ""}|${b.routeKey || ""}|${b.attackId || ""}`
            return aKey.localeCompare(bKey)
        })

    sorted.forEach((obs) => {
        const paramKey = obs.paramKey || "param:<none>"
        if (paramKey.endsWith("<none>")) return
        if (!buckets.has(paramKey)) {
            if (buckets.size >= MAX_PARAM_BUCKETS) return
            buckets.set(paramKey, {
                paramKey,
                count: 0,
                anomalyCount: 0,
                errorCount: 0,
                slowCount: 0,
                routeCounts: new Map(),
                evidenceRefs: []
            })
        }
        const bucket = buckets.get(paramKey)
        bucket.count += 1
        const routeKey = obs.routeKey || "unknown-host|GET|/"
        bucket.routeCounts.set(routeKey, (bucket.routeCounts.get(routeKey) || 0) + 1)
        const status = Number(obs.statusCode || 0)
        const timeMs = Number(obs.timeMs || 0)
        if (!routeStatsByKey.has(routeKey)) {
            routeStatsByKey.set(routeKey, {
                count: 0,
                success2xx: 0,
                fingerprints: new Map()
            })
        }
        const routeStats = routeStatsByKey.get(routeKey)
        routeStats.count += 1
        if (status >= 200 && status < 300) {
            routeStats.success2xx += 1
        }
        const fingerprint = buildResponseFingerprint(obs)
        routeStats.fingerprints.set(fingerprint, (routeStats.fingerprints.get(fingerprint) || 0) + 1)
        const isError = Number.isFinite(status) && status >= 500 && status <= 599
        const isSlow = Number.isFinite(timeMs) && timeMs >= SLOW_REQUEST_MS
        if (isError || isSlow) {
            bucket.anomalyCount += 1
        }
        if (isError) bucket.errorCount += 1
        if (isSlow) bucket.slowCount += 1
        pushEvidence(bucket.evidenceRefs, obs.evidenceRefs || [])
    })

    const ranked = Array.from(buckets.values())
        .filter((bucket) => !isLowValueParam(bucket.paramKey))
        .filter((bucket) => bucket.anomalyCount >= 2 || (bucket.count >= 10 && bucket.anomalyCount >= 1))
        .sort((a, b) => {
            const scoreDelta = scoreBucket(b) - scoreBucket(a)
            if (scoreDelta !== 0) return scoreDelta
            return a.paramKey.localeCompare(b.paramKey)
        })
        .slice(0, MAX_CANDIDATES)

    const patterns = []
    const candidateSeeds = []
    ranked.forEach((bucket) => {
        const topRoute = Array.from(bucket.routeCounts.entries())
            .sort((a, b) => {
                if (b[1] !== a[1]) return b[1] - a[1]
                return a[0].localeCompare(b[0])
            })[0]
        if (!topRoute) return
        const topRouteHits = Number(topRoute[1] || 0)
        if (topRouteHits < MIN_TOP_ROUTE_HITS) return
        const routeKey = topRoute ? topRoute[0] : "unknown-host|GET|/"
        if (isLikelyCatchAllRoute(routeKey, routeStatsByKey)) return
        const routeParts = splitRouteKey(routeKey)
        const routeFanout = bucket.routeCounts.size
        const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        if (!evidenceRefs.length) return
        patterns.push({
            ruleCode: "R4_PARAM_HOTSPOT",
            title: `Parameter hotspot: ${bucket.paramKey.replace(/^param:/, "")}`,
            type: "PARAM_CLUSTER",
            routeKey,
            paramKey: bucket.paramKey,
            priority: scoreBucket(bucket),
            signals: {
                totalHits: bucket.count,
                anomalies: bucket.anomalyCount,
                routeFanout
            },
            evidenceRefs
        })
        const signals = [
            { code: "PARAM_HOTSPOT", value: bucket.anomalyCount, weight: Math.min(18, 8 + bucket.anomalyCount) },
            { code: "PARAM_FANOUT", value: routeFanout, weight: Math.min(12, 4 + routeFanout) }
        ]
        if (bucket.errorCount > 0) {
            signals.push({ code: "REPEATED_5XX", value: bucket.errorCount, weight: 20 })
        }
        if (bucket.slowCount > 0) {
            signals.push({ code: "LATENCY_OUTLIER", value: bucket.slowCount })
        }
        candidateSeeds.push({
            createdByRule: "R4_PARAM_HOTSPOT",
            type: "RUNTIME_ANOMALY",
            title: `Hot parameter candidate on ${routeParts.method} ${routeParts.pathTemplate}`,
            routeKey,
            paramKey: bucket.paramKey,
            engineSignals: ["DAST"],
            repeatabilityCount: bucket.anomalyCount,
            signals,
            evidenceRefs,
            manualSteps: [
                "Open in R-Builder and replay the baseline request before mutation.",
                `Replay requests touching ${bucket.paramKey.replace(/^param:/, "")} with type, length, and encoding variants.`,
                "Probe boundary values and malformed JSON/form payloads to confirm validation gaps.",
                "Check whether anomalies persist across equivalent routes and user roles."
            ]
        })
    })

    return {
        ruleCode: "R4_PARAM_HOTSPOT",
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds
    }
}

export default runRuleParamHotspot
