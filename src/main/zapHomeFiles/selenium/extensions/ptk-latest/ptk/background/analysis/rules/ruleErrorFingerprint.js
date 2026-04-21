import { splitRouteKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const ERROR_FINGERPRINTS = [
    { code: "DB_ERROR_SIGNATURE", name: "SQLSTATE", regex: /SQLSTATE|syntax error at or near|psql:/i },
    { code: "DB_ERROR_SIGNATURE", name: "ORA", regex: /ORA-\d{4,5}/i },
    { code: "DB_ERROR_SIGNATURE", name: "MONGO_ERROR", regex: /Mongo(?:Server)?Error|BSONError/i },
    { code: "STACK_TRACE_FINGERPRINT", name: "STACK_TRACE", regex: /Exception|Traceback \(most recent call last\)| at [A-Za-z0-9_$.<>]+\([^)]*\)/i },
    { code: "TEMPLATE_ERROR_SIGNATURE", name: "TEMPLATE_ERROR", regex: /TemplateSyntaxError|Twig\\Error|Handlebars|Jinja2/i }
]

const MAX_ROUTE_BUCKETS = 2000
const MAX_EVIDENCE_REFS = 10

function firstFingerprint(text) {
    if (!text || typeof text !== "string") return null
    for (const fingerprint of ERROR_FINGERPRINTS) {
        if (fingerprint.regex.test(text)) {
            return fingerprint
        }
    }
    return null
}

function pushEvidence(target = [], refs = []) {
    if (!Array.isArray(refs)) return
    refs.forEach((ref) => {
        if (!ref || typeof ref !== "object") return
        if (target.length >= MAX_EVIDENCE_REFS) return
        target.push(ref)
    })
}

export function runRuleErrorFingerprint(context = {}) {
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
        const fingerprint = firstFingerprint(obs.responseText || "")
        if (!fingerprint) return
        const routeKey = obs.routeKey || "unknown-host|GET|/"
        const paramKey = obs.paramKey || "param:<none>"
        const key = `${routeKey}|${paramKey}|${fingerprint.name}`
        if (!buckets.has(key)) {
            if (buckets.size >= MAX_ROUTE_BUCKETS) return
            buckets.set(key, {
                routeKey,
                paramKey,
                fingerprint,
                count: 0,
                hasServerError: false,
                evidenceRefs: []
            })
        }
        const bucket = buckets.get(key)
        bucket.count += 1
        const status = Number(obs.statusCode || 0)
        if (Number.isFinite(status) && status >= 500 && status <= 599) {
            bucket.hasServerError = true
        }
        pushEvidence(bucket.evidenceRefs, obs.evidenceRefs || [])
    })

    const patterns = []
    const candidateSeeds = []
    Array.from(buckets.values())
        .sort((a, b) => {
            if (b.count !== a.count) return b.count - a.count
            return `${a.routeKey}|${a.paramKey}|${a.fingerprint.name}`.localeCompare(`${b.routeKey}|${b.paramKey}|${b.fingerprint.name}`)
        })
        .forEach((bucket) => {
            if (bucket.count <= 0) return
            const routeParts = splitRouteKey(bucket.routeKey)
            const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
            patterns.push({
                ruleCode: "R2_ERROR_FINGERPRINT",
                title: `${bucket.fingerprint.name} fingerprint on ${routeParts.method} ${routeParts.pathTemplate}`,
                type: "ERROR_FINGERPRINT",
                routeKey: bucket.routeKey,
                paramKey: bucket.paramKey,
                priority: bucket.count,
                signals: {
                    fingerprint: bucket.fingerprint.name,
                    hits: bucket.count,
                    hasServerError: bucket.hasServerError
                },
                evidenceRefs
            })

            const baseSignals = [
                { code: bucket.fingerprint.code, value: bucket.fingerprint.name }
            ]
            if (bucket.hasServerError) {
                baseSignals.push({ code: "REPEATED_5XX", value: bucket.count, weight: 20 })
            }
            candidateSeeds.push({
                createdByRule: "R2_ERROR_FINGERPRINT",
                type: "RUNTIME_ANOMALY",
                title: `Error fingerprint suggests exploitable edge on ${routeParts.method} ${routeParts.pathTemplate}`,
                routeKey: bucket.routeKey,
                paramKey: bucket.paramKey,
                engineSignals: ["DAST"],
                repeatabilityCount: bucket.count,
                signals: baseSignals,
                evidenceRefs,
                manualSteps: [
                    "Replay the request with minimal payload changes to isolate the exact trigger.",
                    "Validate whether error details leak query fragments, class names, or stack traces.",
                    "Compare behavior for authenticated vs unauthenticated sessions on the same route."
                ]
            })
        })

    return {
        ruleCode: "R2_ERROR_FINGERPRINT",
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds
    }
}

export default runRuleErrorFingerprint
