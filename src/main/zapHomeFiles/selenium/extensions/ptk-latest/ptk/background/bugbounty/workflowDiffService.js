export class WorkflowDiffService {
    diff({ workflowSummary = null, reproductionSteps = [] } = {}) {
        const steps = Array.isArray(workflowSummary?.steps) ? workflowSummary.steps : []
        const workflowLabels = steps.map((step) => String(step?.label || "").trim()).filter(Boolean)
        const reproduction = Array.isArray(reproductionSteps)
            ? reproductionSteps.map((step) => String(step || "").trim()).filter(Boolean)
            : []
        const missingFromWorkflow = reproduction.filter((step) => !workflowLabels.some((label) => step.toLowerCase().includes(label.toLowerCase())))
        return {
            workflowStepCount: workflowLabels.length,
            reproductionStepCount: reproduction.length,
            missingFromWorkflow,
            hasDrift: missingFromWorkflow.length > 0
        }
    }
}

export default WorkflowDiffService
