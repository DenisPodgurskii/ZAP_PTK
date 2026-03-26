function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
}

export function renderReportDraftPreview(draft = null) {
    if (!draft || typeof draft !== "object") {
        return `
            <div class="ui tiny info message">
                <div class="header">No report draft yet</div>
                <p>Save evidence or preview a draft from the current authz diff context.</p>
            </div>
        `
    }
    const steps = Array.isArray(draft?.reproductionSteps) ? draft.reproductionSteps : []
    return `
        <div class="ui tiny segment" style="margin-top:8px;">
            <div class="ui small header" style="margin-bottom:8px;">${escapeHtml(draft?.title || "Report draft")}</div>
            <div><b>Affected Route:</b> ${escapeHtml(draft?.affectedRoute || "unknown")}</div>
            <div style="margin-top:6px;"><b>Summary:</b> ${escapeHtml(draft?.summary || "No summary.")}</div>
            <div style="margin-top:6px;"><b>Actual Result:</b> ${escapeHtml(draft?.actualResult || "No actual result.")}</div>
            <div style="margin-top:6px;"><b>Expected Result:</b> ${escapeHtml(draft?.expectedResult || "No expected result.")}</div>
            <div style="margin-top:6px;"><b>Impact:</b> ${escapeHtml(draft?.impact || "No impact statement.")}</div>
            <div style="margin-top:8px;"><b>Reproduction:</b></div>
            <ol style="margin:6px 0 0 18px; padding:0;">
                ${(steps.length ? steps : ["Replay the candidate request and compare the responses."])
                    .map((step) => `<li>${escapeHtml(step)}</li>`)
                    .join("")}
            </ol>
            <div style="margin-top:8px;">
                <details>
                    <summary>Markdown Draft</summary>
                    <pre style="white-space:pre-wrap; margin-top:8px;">${escapeHtml(draft?.markdown || "")}</pre>
                </details>
            </div>
        </div>
    `
}

export default renderReportDraftPreview
