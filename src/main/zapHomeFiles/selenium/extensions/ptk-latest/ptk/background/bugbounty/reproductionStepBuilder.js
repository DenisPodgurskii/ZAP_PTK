function routeLabel(candidate = {}) {
    return String(candidate?.routeKey || candidate?.title || "candidate").trim() || "candidate"
}

function sessionLabel(session = {}, fallback = "session") {
    return String(session?.label || fallback || "session").trim() || "session"
}

export class ReproductionStepBuilder {
    build({
        candidate = null,
        baselineSession = null,
        comparisonSession = null,
        objectSwap = null,
        workflowSummary = null
    } = {}) {
        const steps = [
            `Open the target route for ${routeLabel(candidate)}.`,
            `Authenticate as ${sessionLabel(baselineSession, "baseline")} and capture the baseline response.`,
            `Authenticate as ${sessionLabel(comparisonSession, "comparison")} and replay the same request.`
        ]
        if (objectSwap?.applied === true && objectSwap?.targetParam) {
            steps.push(`Replace ${objectSwap.targetParam} from ${objectSwap.originalValue ?? "<original>"} to ${objectSwap.swappedValue ?? "<swapped>"} before replay.`)
        }
        steps.push("Compare status, redirect/auth posture, and response body exposure between the two runs.")
        if (workflowSummary?.recordingPresent) {
            steps.push(`Follow the recorded workflow context (${Number(workflowSummary?.stepCount || 0)} step${Number(workflowSummary?.stepCount || 0) === 1 ? "" : "s"}) before replay if the target requires stateful navigation.`)
        }
        return steps
    }
}

export default ReproductionStepBuilder
