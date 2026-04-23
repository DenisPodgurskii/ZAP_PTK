function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
}

export function renderDiffSummary(diff = null) {
    if (!diff || typeof diff !== "object") return ""
    const result = diff?.result && typeof diff.result === "object" ? diff.result : {}
    const responseDiff = diff?.responseDiff && typeof diff.responseDiff === "object" ? diff.responseDiff : {}
    const indicators = responseDiff?.indicators && typeof responseDiff.indicators === "object" ? responseDiff.indicators : {}
    const activeSignals = Object.entries(indicators).filter(([, value]) => value === true).map(([key]) => key)
    return `
        <div class="ui tiny segment" style="margin-top:8px;">
            <div><b>Diff Category:</b> ${escapeHtml(result?.category || "NO_DIFFERENCE")}</div>
            <div style="margin-top:4px;"><b>Summary:</b> ${escapeHtml(result?.summary || "No diff summary.")}</div>
            <div style="margin-top:4px;"><b>Signals:</b> ${activeSignals.length ? activeSignals.map((signal) => `<span class="ui tiny basic label">${escapeHtml(signal)}</span>`).join(" ") : '<span class="ui tiny basic label">none</span>'}</div>
        </div>
    `
}

export default renderDiffSummary
