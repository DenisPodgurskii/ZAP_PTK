function safe(value, fallback = "") {
    const normalized = String(value ?? "").trim()
    return normalized || fallback
}

function sessionLabel(session = {}, fallback = "session") {
    return safe(session?.label, fallback)
}

export class ReportDraftBuilder {
    build({ evidencePackage = null } = {}) {
        const evidence = evidencePackage && typeof evidencePackage === "object" ? evidencePackage : {}
        const diff = evidence?.diff && typeof evidence.diff === "object" ? evidence.diff : {}
        const result = diff?.result && typeof diff.result === "object" ? diff.result : {}
        const routeKey = safe(evidence?.routeKey, "unknown route")
        const title = safe(evidence?.title, `${safe(result?.category, "Bug bounty")} on ${routeKey}`)
        const summary = safe(evidence?.summary, safe(result?.summary, "Behavior changes between compared sessions."))
        const baselineLabel = sessionLabel(evidence?.sessions?.baseline, "baseline")
        const comparisonLabel = sessionLabel(evidence?.sessions?.comparison, "comparison")
        const expectedResult = `${baselineLabel} and ${comparisonLabel} should receive equivalent access and data exposure unless explicitly authorized otherwise.`
        const actualResult = safe(result?.summary, "Compared sessions returned materially different results.")
        const impact = result?.category === "OBJECT_ACCESS_DELTA"
            ? "An attacker may access or influence a different object than intended by changing the target identifier."
            : (result?.category === "ACCESS_CONTROL_DELTA"
                ? "An attacker may gain a different access outcome by replaying the same request under a different session."
                : "The compared responses suggest a role, tenant, or authorization boundary weakness that warrants validation.")
        const reproductionSteps = Array.isArray(evidence?.reproductionSteps) ? evidence.reproductionSteps : []
        const markdown = [
            `# ${title}`,
            "",
            "## Summary",
            summary,
            "",
            "## Affected Route",
            `- \`${routeKey}\``,
            "",
            "## Sessions",
            `- Baseline: ${baselineLabel}`,
            `- Comparison: ${comparisonLabel}`,
            "",
            "## Reproduction Steps",
            ...(reproductionSteps.length
                ? reproductionSteps.map((step, index) => `${index + 1}. ${step}`)
                : ["1. Replay the same candidate request across the two chosen sessions.", "2. Compare the returned responses."]),
            "",
            "## Actual Result",
            actualResult,
            "",
            "## Expected Result",
            expectedResult,
            "",
            "## Impact",
            impact
        ].join("\n")

        return {
            title,
            summary,
            affectedRoute: routeKey,
            actualResult,
            expectedResult,
            impact,
            sessions: {
                baseline: baselineLabel,
                comparison: comparisonLabel
            },
            reproductionSteps,
            markdown
        }
    }
}

export default ReportDraftBuilder
