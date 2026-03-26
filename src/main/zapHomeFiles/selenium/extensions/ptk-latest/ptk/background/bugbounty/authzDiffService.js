import { ResponseDiffService } from "./responseDiffService.js"

function normalizeMethod(value) {
    const method = String(value || "GET").trim().toUpperCase()
    return method || "GET"
}

function normalizeSessionSummary(session = {}, fallbackLabel = "session") {
    return {
        id: session?.id || null,
        label: String(session?.label || fallbackLabel || "session").trim() || "session",
        relation: String(session?.relation || "").trim().toLowerCase() || "peer"
    }
}

function buildSummary(category, baselineLabel, comparisonLabel) {
    switch (category) {
        case "ACCESS_CONTROL_DELTA":
            return `${comparisonLabel} received a different access outcome than ${baselineLabel}.`
        case "OBJECT_ACCESS_DELTA":
            return `${comparisonLabel} received a different object access outcome than ${baselineLabel}.`
        case "EXPOSURE_DELTA":
            return `${comparisonLabel} received different response data exposure than ${baselineLabel}.`
        case "REDIRECT_DELTA":
            return `${comparisonLabel} followed a different redirect/auth flow than ${baselineLabel}.`
        case "MUTATION_OUTCOME_DELTA":
            return `${comparisonLabel} triggered a different mutation outcome than ${baselineLabel}.`
        case "RESPONSE_DRIFT":
            return `${comparisonLabel} received a materially different response than ${baselineLabel}.`
        default:
            return `${comparisonLabel} and ${baselineLabel} produced no meaningful authorization difference.`
    }
}

export class AuthzDiffService {
    constructor({
        responseDiffService = new ResponseDiffService()
    } = {}) {
        this.responseDiffService = responseDiffService
    }

    evaluate({
        request = {},
        baseline = {},
        comparison = {},
        objectSwap = null
    } = {}) {
        const requestMethod = normalizeMethod(request?.method || baseline?.request?.method || comparison?.request?.method || "GET")
        const baselineSession = normalizeSessionSummary(baseline?.session, "baseline")
        const comparisonSession = normalizeSessionSummary(comparison?.session, "comparison")
        const responseDiff = this.responseDiffService.diffResponses({
            baseline: baseline?.response || baseline,
            comparison: comparison?.response || comparison,
            requestMethod
        })

        let category = "NO_DIFFERENCE"
        let confidence = "low"
        let priority = 0
        const rationale = []

        if (responseDiff.meaningfulDifference) {
            if (objectSwap?.applied === true && (responseDiff.indicators.authPostureChanged || responseDiff.indicators.fieldExposureChanged || responseDiff.indicators.statusChanged)) {
                category = "OBJECT_ACCESS_DELTA"
                confidence = "high"
                priority = 90
                rationale.push("Object identifier change produced a different access or data exposure result.")
            } else if (responseDiff.indicators.authPostureChanged || responseDiff.indicators.statusChanged) {
                category = "ACCESS_CONTROL_DELTA"
                confidence = "high"
                priority = 80
                rationale.push("Compared sessions produced different authorization outcomes.")
            } else if (responseDiff.indicators.fieldExposureChanged) {
                category = "EXPOSURE_DELTA"
                confidence = "medium"
                priority = 70
                rationale.push("Compared sessions exposed a different JSON response shape.")
            } else if (responseDiff.indicators.redirectChanged) {
                category = "REDIRECT_DELTA"
                confidence = "medium"
                priority = 55
                rationale.push("Compared sessions followed different login or redirect flows.")
            } else if (responseDiff.indicators.mutationOutcomeChanged) {
                category = "MUTATION_OUTCOME_DELTA"
                confidence = "medium"
                priority = 65
                rationale.push("Compared sessions produced different mutation outcomes.")
            } else if (responseDiff.indicators.headerChanged || responseDiff.indicators.bodyChanged) {
                category = "RESPONSE_DRIFT"
                confidence = "low"
                priority = 40
                rationale.push("Compared sessions produced a materially different response.")
            }
        }

        return {
            requestMethod,
            baselineSession,
            comparisonSession,
            objectSwap: objectSwap && typeof objectSwap === "object"
                ? {
                    applied: objectSwap.applied === true,
                    targetParam: objectSwap.targetParam || null,
                    originalValue: objectSwap.originalValue || null,
                    swappedValue: objectSwap.swappedValue || null
                }
                : null,
            responseDiff,
            result: {
                category,
                confidence,
                priority,
                meaningfulDifference: responseDiff.meaningfulDifference,
                summary: buildSummary(category, baselineSession.label, comparisonSession.label),
                rationale: rationale.concat(responseDiff.observations)
            }
        }
    }
}

export default AuthzDiffService
