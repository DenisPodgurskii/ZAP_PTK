import CryptoES from "../../packages/crypto-es/index.js"
import { buildRouteFamilyKey, normalizeEngineName, normalizeParamKey } from "./canonicalize.js"
import { buildStableEvidenceKeySet, normalizeEvidenceRefs } from "./evidenceRefs.js"

const IMPACT_SIGNAL_CODES = new Set([
    "REPEATED_5XX",
    "STACK_TRACE_FINGERPRINT",
    "DB_ERROR_SIGNATURE",
    "TEMPLATE_ERROR_SIGNATURE"
])

const EXPLOITABILITY_SIGNAL_CODES = new Set([
    "PARAM_HOTSPOT",
    "PARAM_FANOUT",
    "LATENCY_OUTLIER",
    "AUTH_SESSION_SIGNAL",
    "RESOURCE_BEHAVIOR_DRIFT"
])

const SIGNAL_WEIGHTS = Object.freeze({
    REPEATED_5XX: 25,
    STACK_TRACE_FINGERPRINT: 20,
    DB_ERROR_SIGNATURE: 20,
    TEMPLATE_ERROR_SIGNATURE: 15,
    PARAM_HOTSPOT: 10,
    PARAM_FANOUT: 8,
    LATENCY_OUTLIER: 15,
    AUTH_SESSION_SIGNAL: 10,
    RESOURCE_BEHAVIOR_DRIFT: 12
})

const CONFIDENCE_RANK = Object.freeze({
    low: 1,
    medium: 2,
    high: 3
})

export const CANDIDATE_RELEVANT_ENGINES = Object.freeze({
    RUNTIME_ANOMALY: ["DAST", "IAST"],
    CODE_HOTSPOT: ["SAST"],
    DEPENDENCY_RISK: ["SCA"],
    AUTHZ_INCONSISTENCY: ["DAST", "IAST"]
})

function clamp(num, min, max) {
    return Math.min(max, Math.max(min, num))
}

function stableStringify(value) {
    if (value === null || value === undefined) return ""
    if (typeof value === "number" || typeof value === "boolean") return String(value)
    if (typeof value === "string") return value
    if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`
    if (typeof value === "object") {
        const keys = Object.keys(value).sort((a, b) => a.localeCompare(b))
        return `{${keys.map((key) => `${key}:${stableStringify(value[key])}`).join(",")}}`
    }
    return String(value)
}

function hashHex(payload) {
    return CryptoES.SHA256(String(payload || "")).toString(CryptoES.enc.Hex)
}

function normalizeSignals(signals = []) {
    if (!Array.isArray(signals)) return []
    return signals
        .filter((signal) => signal && typeof signal === "object")
        .map((signal) => ({
            code: String(signal.code || signal.signal || "UNKNOWN_SIGNAL"),
            value: signal.value,
            weight: Number.isFinite(signal.weight) ? Number(signal.weight) : null
        }))
}

function buildSignalDigest(signals = []) {
    const list = normalizeSignals(signals)
        .map((signal) => `${signal.code}:${stableStringify(signal.value)}`)
        .sort((a, b) => a.localeCompare(b))
    return list.join("|")
}

function signalScoreMap(signals = []) {
    const map = new Map()
    normalizeSignals(signals).forEach((signal) => {
        const weighted = Number.isFinite(signal.weight)
            ? Number(signal.weight)
            : Number(SIGNAL_WEIGHTS[signal.code] || 0)
        const prev = map.get(signal.code) || 0
        if (weighted > prev) {
            map.set(signal.code, weighted)
        }
    })
    return map
}

function computeRepeatabilityScore(seed, evidenceRefs = []) {
    const seedCount = Number(seed?.repeatabilityCount || 0)
    const fallbackCount = Array.isArray(evidenceRefs) ? evidenceRefs.length : 0
    const count = Math.max(seedCount, fallbackCount)
    if (count >= 8) return 20
    if (count >= 5) return 16
    if (count >= 3) return 12
    if (count >= 2) return 8
    if (count >= 1) return 4
    return 0
}

function computeCrossEngineBoost(seed, context, primaryEngine) {
    const seedEngines = new Set((seed?.engineSignals || []).map((engine) => normalizeEngineName(engine)).filter(Boolean))
    if (seedEngines.size > 1) {
        return { value: 20, reason: Array.from(seedEngines).sort((a, b) => a.localeCompare(b)).join("+") }
    }
    const routeFamily = buildRouteFamilyKey(seed?.routeKey)
    const routeEngines = context?.routeEnginesByFamily?.get(routeFamily)
    if (routeEngines && routeEngines.size > 1) {
        const hasOtherEngine = Array.from(routeEngines).some((engine) => engine !== primaryEngine)
        if (hasOtherEngine) {
            return { value: 20, reason: Array.from(routeEngines).sort((a, b) => a.localeCompare(b)).join("+") }
        }
    }
    return { value: 0, reason: null }
}

function computeCoveragePenalty(seed, context) {
    let penalty = 0
    const reasons = []
    const relevantEngines = CANDIDATE_RELEVANT_ENGINES[seed?.type] || []
    const present = context?.enginesPresentSet || new Set()
    if (relevantEngines.length) {
        const missing = relevantEngines.filter((engine) => !present.has(engine))
        if (missing.length) {
            penalty += 15
            reasons.push({
                signal: "MISSING_RELEVANT_ENGINE",
                value: missing.join(",")
            })
        }
    }
    const coverageScore = Number(context?.coverage?.confidenceScore || 0)
    if (coverageScore > 0 && coverageScore < 45) {
        penalty += 10
        reasons.push({
            signal: "LOW_COVERAGE",
            value: coverageScore
        })
    }
    return { penalty, reasons }
}

function classifyConfidence(score, coveragePenalty) {
    if (score >= 75 && coveragePenalty <= 10) return "high"
    if (score >= 45) return "medium"
    return "low"
}

function buildCandidateId({ ruleCode, routeKey, paramKey, stableEvidenceKeySet, signalDigest }) {
    const payload = [
        ruleCode || "",
        routeKey || "",
        paramKey || "",
        stableEvidenceKeySet || "",
        signalDigest || ""
    ].join("|")
    return `cand_${hashHex(payload).slice(0, 24)}`
}

function buildSuppressKey({ ruleCode, routeKey, paramKey }) {
    const payload = [ruleCode || "", routeKey || "", paramKey || ""].join("|")
    return `sup_${hashHex(payload).slice(0, 24)}`
}

export function scoreCandidateSeeds(candidateSeeds = [], context = {}) {
    if (!Array.isArray(candidateSeeds) || !candidateSeeds.length) return []
    const enginesPresent = Array.isArray(context?.enginesPresent) ? context.enginesPresent : []
    const enginesPresentSet = new Set(enginesPresent.map((engine) => normalizeEngineName(engine)).filter(Boolean))
    const scored = candidateSeeds
        .filter((seed) => seed && typeof seed === "object")
        .map((seed) => {
            const routeKey = String(seed.routeKey || "unknown-host|GET|/")
            const paramKey = (typeof seed.paramKey === "string" && seed.paramKey.includes(":"))
                ? seed.paramKey
                : normalizeParamKey(seed.paramKey || "<none>", "param")
            const evidenceRefs = normalizeEvidenceRefs(seed.evidenceRefs || [], { maxRefs: 12 })
            const stableEvidenceKeySet = buildStableEvidenceKeySet(evidenceRefs)
            const signals = normalizeSignals(seed.signals || [])
            const signalDigest = buildSignalDigest(signals)
            const scoreMap = signalScoreMap(signals)

            let impact = 0
            let exploitability = 0
            scoreMap.forEach((weight, code) => {
                if (IMPACT_SIGNAL_CODES.has(code)) {
                    impact += weight
                    return
                }
                if (EXPLOITABILITY_SIGNAL_CODES.has(code)) {
                    exploitability += weight
                    return
                }
                exploitability += weight
            })

            const repeatability = computeRepeatabilityScore(seed, evidenceRefs)
            const primaryEngine = normalizeEngineName((seed.engineSignals || [])[0]) || normalizeEngineName(seed.engine) || null
            const crossEngine = computeCrossEngineBoost(seed, context, primaryEngine)
            const coveragePenaltyResult = computeCoveragePenalty(seed, {
                coverage: context?.coverage,
                enginesPresentSet
            })
            const rawScore = impact + exploitability + repeatability + crossEngine.value - coveragePenaltyResult.penalty
            const score = clamp(Math.round(rawScore), 0, 100)
            const confidence = classifyConfidence(score, coveragePenaltyResult.penalty)

            const why = []
            signals
                .slice()
                .sort((a, b) => a.code.localeCompare(b.code))
                .forEach((signal) => {
                    why.push({
                        signal: signal.code,
                        value: signal.value
                    })
                })
            if (crossEngine.value > 0) {
                why.push({
                    signal: "CROSS_ENGINE_CORROBORATION",
                    value: crossEngine.reason || "MULTI_ENGINE"
                })
            }
            coveragePenaltyResult.reasons.forEach((reason) => why.push(reason))

            const createdByRule = String(seed.createdByRule || seed.ruleCode || "RULE_UNKNOWN")
            const id = buildCandidateId({
                ruleCode: createdByRule,
                routeKey,
                paramKey,
                stableEvidenceKeySet,
                signalDigest
            })
            const suppressKey = buildSuppressKey({
                ruleCode: createdByRule,
                routeKey,
                paramKey
            })
            const engineSignals = Array.from(
                new Set((seed.engineSignals || [])
                    .map((engine) => normalizeEngineName(engine))
                    .filter(Boolean))
            ).sort((a, b) => a.localeCompare(b))

            return {
                id,
                suppressKey,
                type: seed.type || "RUNTIME_ANOMALY",
                title: seed.title || "Manual investigation candidate",
                score,
                confidence,
                confidenceRank: CONFIDENCE_RANK[confidence] || 1,
                routeKey,
                paramKey,
                engineSignals,
                why,
                evidenceRefs,
                manualSteps: Array.isArray(seed.manualSteps) ? seed.manualSteps.slice(0, 5) : [],
                createdByRule
            }
        })

    return scored.sort((a, b) => {
        if (b.score !== a.score) return b.score - a.score
        return a.id.localeCompare(b.id)
    })
}
