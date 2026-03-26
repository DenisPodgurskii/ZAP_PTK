import { renderDiffSummary } from "./report/diffRenderer.js"
import { renderReportDraftPreview } from "./report/reportDraftRenderer.js"

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
}

function escapeAttr(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
}

function normalizeComparableHeaders(headers) {
    if (Array.isArray(headers)) return headers
    if (headers && typeof headers === "object") {
        return Object.entries(headers).map(([name, value]) => ({
            name,
            value: Array.isArray(value) ? value.join(", ") : String(value ?? "")
        }))
    }
    return []
}

function pickFirstResponseArtifact(run = {}) {
    const direct = [
        run?.artifacts?.response,
        run?.artifacts?.lastResponse,
        run?.summary?.response,
        run?.response
    ].find((entry) => entry && typeof entry === "object")
    if (direct) return direct

    const networkResponses = Array.isArray(run?.artifacts?.network?.responses)
        ? run.artifacts.network.responses
        : []
    if (networkResponses.length) return networkResponses[networkResponses.length - 1]

    const networkEntries = Array.isArray(run?.artifacts?.network?.entries)
        ? run.artifacts.network.entries
        : []
    const entryResponse = networkEntries
        .map((entry) => entry?.response)
        .filter((entry) => entry && typeof entry === "object")
        .pop()
    if (entryResponse) return entryResponse

    return null
}

export function extractComparableResponseFromRun(run = {}) {
    const response = pickFirstResponseArtifact(run)
    if (!response || typeof response !== "object") return null
    const headers = normalizeComparableHeaders(response?.headers || response?.responseHeaders || {})
    return {
        status: response?.status ?? response?.statusCode ?? null,
        statusCode: response?.statusCode ?? response?.status ?? null,
        headers,
        body: typeof response?.body === "string"
            ? response.body
            : (typeof response?.text === "string"
                ? response.text
                : (response?.body && typeof response.body === "object"
                    ? JSON.stringify(response.body)
                    : "")),
        url: response?.url || null
    }
}

export function renderSessionProfileOptions(profiles = [], {
    selectedId = "",
    placeholder = "Select session profile",
    includeEmpty = true
} = {}) {
    const entries = Array.isArray(profiles) ? profiles : []
    const options = []
    if (includeEmpty) {
        const emptySelected = !selectedId ? " selected" : ""
        options.push(`<option value=""${emptySelected}>${escapeHtml(placeholder)}</option>`)
    }
    entries.forEach((profile) => {
        const id = String(profile?.id || "").trim()
        if (!id) return
        const selected = id === String(selectedId || "").trim() ? " selected" : ""
        const label = String(profile?.label || id).trim() || id
        const cookieCount = Number(profile?.cookieCount || 0)
        const host = String(profile?.host || "").trim()
        options.push(
            `<option value="${escapeAttr(id)}"${selected}>${escapeHtml(label)}${cookieCount ? ` (${cookieCount} cookies)` : ""}${host ? ` - ${escapeHtml(host)}` : ""}</option>`
        )
    })
    return options.join("")
}

export function renderSessionProfileListHtml({
    host = "",
    profiles = []
} = {}) {
    const entries = Array.isArray(profiles) ? profiles : []
    const hostLabel = String(host || "").trim()
    if (!entries.length) {
        return `
            <div class="ui info message">
                <div class="header">No session profiles yet</div>
                <p>Create a local session snapshot for ${escapeHtml(hostLabel || "this host")} to reuse it in bug bounty flows.</p>
            </div>
        `
    }
    return `
        <div class="ui relaxed divided list">
            ${entries.map((profile) => {
                const id = String(profile?.id || "").trim()
                const label = String(profile?.label || id).trim() || id
                const notes = String(profile?.notes || "").trim()
                const cookieCount = Number(profile?.cookieCount || 0)
                return `
                    <div class="item">
                        <div class="right floated content">
                            <button type="button" class="ui tiny basic red button delete_session_profile" data-session-profile-id="${escapeAttr(id)}">Delete</button>
                        </div>
                        <div class="content">
                            <div class="header">${escapeHtml(label)}</div>
                            <div class="description" style="margin-top:4px;">
                                ${cookieCount} cookie${cookieCount === 1 ? "" : "s"}
                                ${profile?.updatedAt ? ` | Updated ${escapeHtml(profile.updatedAt)}` : ""}
                                ${notes ? `<div style="margin-top:4px;">${escapeHtml(notes)}</div>` : ""}
                            </div>
                        </div>
                    </div>
                `
            }).join("")}
        </div>
    `
}

function categoryColor(category = "") {
    const normalized = String(category || "").trim().toUpperCase()
    if (normalized === "OBJECT_ACCESS_DELTA" || normalized === "ACCESS_CONTROL_DELTA") return "red"
    if (normalized === "EXPOSURE_DELTA" || normalized === "MUTATION_OUTCOME_DELTA") return "orange"
    if (normalized === "REDIRECT_DELTA") return "yellow"
    if (normalized === "NO_DIFFERENCE") return "green"
    return "grey"
}

function humanizeCategory(category = "") {
    return String(category || "NO_DIFFERENCE")
        .toLowerCase()
        .split("_")
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ")
}

export function renderAuthzDiffResultHtml(diff = null) {
    if (!diff || typeof diff !== "object") {
        return `
            <div class="ui info message">
                <div class="header">No authz diff yet</div>
                <p>Run the automated diff first. Manual JSON comparison is available in Advanced.</p>
            </div>
        `
    }

    const result = diff?.result && typeof diff.result === "object" ? diff.result : {}
    const responseDiff = diff?.responseDiff && typeof diff.responseDiff === "object" ? diff.responseDiff : {}
    const baselineSession = diff?.baselineSession && typeof diff.baselineSession === "object" ? diff.baselineSession : {}
    const comparisonSession = diff?.comparisonSession && typeof diff.comparisonSession === "object" ? diff.comparisonSession : {}
    const objectSwap = diff?.objectSwap && typeof diff.objectSwap === "object" ? diff.objectSwap : null
    const indicators = responseDiff?.indicators && typeof responseDiff.indicators === "object" ? responseDiff.indicators : {}
    const observations = Array.isArray(result?.rationale) ? result.rationale : []

    return `
        <div class="ui ${categoryColor(result?.category)} message">
            <div class="header">${escapeHtml(result?.summary || "Authz diff result")}</div>
            <div style="margin-top:6px;">
                <span class="ui tiny ${categoryColor(result?.category)} label">${escapeHtml(humanizeCategory(result?.category || "NO_DIFFERENCE"))}</span>
                <span class="ui tiny basic label">Confidence ${escapeHtml(String(result?.confidence || "low"))}</span>
                <span class="ui tiny basic label">Priority ${escapeHtml(String(result?.priority ?? 0))}</span>
            </div>
            <div style="margin-top:8px;">
                <div><b>Baseline:</b> ${escapeHtml(baselineSession?.label || "baseline")}</div>
                <div><b>Comparison:</b> ${escapeHtml(comparisonSession?.label || "comparison")}</div>
            </div>
            <div style="margin-top:8px;">
                <div><b>Status:</b> ${escapeHtml(String(responseDiff?.baseline?.status ?? "unknown"))} -> ${escapeHtml(String(responseDiff?.comparison?.status ?? "unknown"))}</div>
                <div><b>Auth posture:</b> ${escapeHtml(String(responseDiff?.baseline?.authPosture || "unknown"))} -> ${escapeHtml(String(responseDiff?.comparison?.authPosture || "unknown"))}</div>
                <div><b>Redirect:</b> ${escapeHtml(String(responseDiff?.baseline?.redirectLocation || "none"))} -> ${escapeHtml(String(responseDiff?.comparison?.redirectLocation || "none"))}</div>
            </div>
            ${objectSwap?.targetParam
                ? `
                    <div style="margin-top:8px;">
                        <b>Object Swap:</b>
                        <span class="ui tiny basic label">${escapeHtml(String(objectSwap.targetParam || "target"))}</span>
                        <span class="ui tiny basic label">${escapeHtml(String(objectSwap.originalValue ?? "<original>"))} -> ${escapeHtml(String(objectSwap.swappedValue ?? "<swapped>"))}</span>
                    </div>
                `
                : ""}
            <div style="margin-top:8px;">
                <b>Signals:</b>
                ${Object.entries(indicators)
                    .filter(([, value]) => value === true)
                    .map(([key]) => `<span class="ui tiny basic label">${escapeHtml(key)}</span>`)
                    .join(" ") || '<span class="ui tiny basic label">none</span>'}
            </div>
            ${observations.length
                ? `
                    <div style="margin-top:8px;">
                        <b>Rationale:</b>
                        <ul style="margin:6px 0 0 18px;padding:0;">
                            ${observations.slice(0, 6).map((entry) => `<li>${escapeHtml(entry)}</li>`).join("")}
                        </ul>
                    </div>
                `
                : ""}
            ${renderDiffSummary(diff)}
        </div>
    `
}

function humanizeRunStage(stage = "") {
    return String(stage || "queued")
        .toLowerCase()
        .split("_")
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ")
}

function runStatusColor(status = "") {
    const normalized = String(status || "").trim().toLowerCase()
    if (normalized === "completed") return "green"
    if (normalized === "failed" || normalized === "canceled" || normalized === "timed_out") return "red"
    if (normalized === "running") return "blue"
    return "grey"
}

export function renderAuthzDiffRunStatusHtml(run = null) {
    if (!run || typeof run !== "object") {
        return `
            <div class="ui tiny info message">
                <div class="header">No automated authz diff run yet</div>
                <p>Choose two local session profiles and run the same request across both accounts.</p>
            </div>
        `
    }
    const baselineSession = run?.baselineSession && typeof run.baselineSession === "object" ? run.baselineSession : {}
    const comparisonSession = run?.comparisonSession && typeof run.comparisonSession === "object" ? run.comparisonSession : {}
    const baselineRun = run?.baselineRun && typeof run.baselineRun === "object" ? run.baselineRun : {}
    const comparisonRun = run?.comparisonRun && typeof run.comparisonRun === "object" ? run.comparisonRun : {}
    const objectSwap = run?.objectSwap && typeof run.objectSwap === "object" ? run.objectSwap : null
    const error = String(run?.error || "").trim()
    return `
        <div class="ui tiny ${runStatusColor(run?.status)} message">
            <div class="header">Automated Authz Diff</div>
            <div style="margin-top:6px;">
                <span class="ui tiny ${runStatusColor(run?.status)} label">${escapeHtml(String(run?.status || "queued"))}</span>
                <span class="ui tiny basic label">${escapeHtml(humanizeRunStage(run?.stage || "queued"))}</span>
            </div>
            <div style="margin-top:8px;">
                <div><b>Baseline:</b> ${escapeHtml(baselineSession?.label || "baseline")} <span class="ui tiny basic label">${escapeHtml(String(baselineRun?.status || "queued"))}</span></div>
                <div><b>Comparison:</b> ${escapeHtml(comparisonSession?.label || "comparison")} <span class="ui tiny basic label">${escapeHtml(String(comparisonRun?.status || "queued"))}</span></div>
            </div>
            ${objectSwap?.targetParam ? `<div style="margin-top:8px;"><b>Object Swap:</b> ${escapeHtml(String(objectSwap.targetParam))} -> ${escapeHtml(String(objectSwap.swappedValue ?? "<swapped>"))}</div>` : ""}
            ${error ? `<div style="margin-top:8px;" class="ui tiny red text">${escapeHtml(error)}</div>` : ""}
        </div>
    `
}

export function renderObjectSwapSummaryHtml(objectSwap = null) {
    if (!objectSwap || typeof objectSwap !== "object" || !objectSwap?.targetParam) {
        return `
            <div class="ui tiny info message">
                <div class="header">No object swap configured</div>
                <p>Use a candidate parameter or path segment as the swap target before running the diff.</p>
            </div>
        `
    }
    return `
        <div class="ui tiny message">
            <div class="header">Object Swap</div>
            <div style="margin-top:6px;">
                <span class="ui tiny basic label">${escapeHtml(String(objectSwap.location || "param"))}</span>
                <span class="ui tiny basic label">${escapeHtml(String(objectSwap.targetParam || "target"))}</span>
                <span class="ui tiny basic label">${escapeHtml(String(objectSwap.originalValue ?? "<original>"))} -> ${escapeHtml(String(objectSwap.swappedValue ?? "<swapped>"))}</span>
            </div>
        </div>
    `
}

export function renderEvidencePackageSummaryHtml(evidencePackage = null) {
    if (!evidencePackage || typeof evidencePackage !== "object") {
        return `
            <div class="ui tiny info message">
                <div class="header">No evidence package yet</div>
                <p>Save the current authz diff context to capture a reusable evidence bundle.</p>
            </div>
        `
    }
    const sessions = evidencePackage?.sessions && typeof evidencePackage.sessions === "object" ? evidencePackage.sessions : {}
    return `
        <div class="ui tiny segment" style="margin-top:8px;">
            <div class="ui small header" style="margin-bottom:8px;">${escapeHtml(evidencePackage?.title || "Evidence package")}</div>
            <div><b>Route:</b> ${escapeHtml(String(evidencePackage?.routeKey || "unknown"))}</div>
            <div style="margin-top:4px;"><b>Sessions:</b> ${escapeHtml(String(sessions?.baseline?.label || "baseline"))} -> ${escapeHtml(String(sessions?.comparison?.label || "comparison"))}</div>
            <div style="margin-top:4px;"><b>Summary:</b> ${escapeHtml(String(evidencePackage?.summary || evidencePackage?.diff?.result?.summary || "No summary."))}</div>
        </div>
    `
}

export function renderEvidencePackageListHtml({
    evidencePackages = [],
    activeEvidencePackageId = ""
} = {}) {
    const entries = Array.isArray(evidencePackages) ? evidencePackages : []
    const activeId = String(activeEvidencePackageId || "").trim()
    if (!entries.length) {
        return `
            <div class="ui tiny info message">
                <div class="header">No saved evidence packages</div>
                <p>Save evidence from the current authz diff context to build a local package history for this candidate.</p>
            </div>
        `
    }
    return `
        <div class="ui tiny segment" style="margin-top:8px;">
            <div class="ui small header" style="margin-bottom:8px;">Saved Evidence Packages</div>
            <div class="ui relaxed divided list">
                ${entries.map((entry) => {
                    const id = String(entry?.id || "").trim()
                    const title = String(entry?.title || entry?.summary || id || "Evidence package").trim()
                    const isActive = activeId && activeId === id
                    return `
                        <div class="item">
                            <div class="right floated content" style="display:flex; gap:6px; flex-wrap:wrap; justify-content:flex-end;">
                                <button type="button" class="ui tiny basic button open_evidence_package_report" data-evidence-package-id="${escapeAttr(id)}">Open Report</button>
                                <button type="button" class="ui tiny basic button export_evidence_package" data-evidence-package-id="${escapeAttr(id)}" data-export-format="markdown">Export MD</button>
                                <button type="button" class="ui tiny basic button export_evidence_package" data-evidence-package-id="${escapeAttr(id)}" data-export-format="json">Export JSON</button>
                            </div>
                            <div class="content">
                                <div class="header">
                                    ${escapeHtml(title)}
                                    ${isActive ? '<span class="ui tiny blue basic label" style="margin-left:6px;">Current</span>' : ''}
                                </div>
                                <div class="description" style="margin-top:4px;">
                                    ${entry?.createdAt ? `<span>${escapeHtml(String(entry.createdAt))}</span>` : ""}
                                    ${entry?.diffCategory ? `<span class="ui tiny basic label" style="margin-left:6px;">${escapeHtml(String(entry.diffCategory))}</span>` : ""}
                                    ${entry?.routeKey ? `<div style="margin-top:4px;"><code>${escapeHtml(String(entry.routeKey))}</code></div>` : ""}
                                    ${entry?.summary ? `<div style="margin-top:4px;">${escapeHtml(String(entry.summary))}</div>` : ""}
                                </div>
                            </div>
                        </div>
                    `
                }).join("")}
            </div>
        </div>
    `
}

export function renderEvidencePackageDetailHtml(evidencePackage = null, {
    reportDraft = null
} = {}) {
    if (!evidencePackage || typeof evidencePackage !== "object") {
        return `
            <div class="ui tiny info message">
                <div class="header">No evidence package loaded</div>
                <p>Select or save an evidence package first.</p>
            </div>
        `
    }
    const sessions = evidencePackage?.sessions && typeof evidencePackage.sessions === "object" ? evidencePackage.sessions : {}
    const steps = Array.isArray(evidencePackage?.reproductionSteps) ? evidencePackage.reproductionSteps : []
    const requestJson = escapeHtml(JSON.stringify(evidencePackage?.request || {}, null, 2))
    const baselineResponseJson = escapeHtml(JSON.stringify(evidencePackage?.baselineResponse || {}, null, 2))
    const comparisonResponseJson = escapeHtml(JSON.stringify(evidencePackage?.comparisonResponse || {}, null, 2))
    return `
        <div class="ui segment">
            <div class="ui large header">${escapeHtml(evidencePackage?.title || "Evidence package")}</div>
            <div class="ui tiny grey text" style="margin-top:-4px;">
                ${evidencePackage?.createdAt ? `Saved ${escapeHtml(String(evidencePackage.createdAt))}` : "Saved locally"}
            </div>
            <div style="margin-top:10px;">
                <div><b>Route:</b> ${escapeHtml(String(evidencePackage?.routeKey || "unknown"))}</div>
                <div style="margin-top:4px;"><b>Sessions:</b> ${escapeHtml(String(sessions?.baseline?.label || "baseline"))} -> ${escapeHtml(String(sessions?.comparison?.label || "comparison"))}</div>
                <div style="margin-top:4px;"><b>Summary:</b> ${escapeHtml(String(evidencePackage?.summary || evidencePackage?.diff?.result?.summary || "No summary."))}</div>
            </div>
            <div style="margin-top:10px;">${renderObjectSwapSummaryHtml(evidencePackage?.objectSwap || null)}</div>
            <div style="margin-top:10px;">${renderAuthzDiffResultHtml(evidencePackage?.diff || null)}</div>
            <div style="margin-top:10px;">${renderWorkflowOverlaySummaryHtml(evidencePackage?.workflowSummary || null)}</div>
            <div class="ui tiny segment" style="margin-top:10px;">
                <div class="ui small header" style="margin-bottom:8px;">Reproduction Steps</div>
                <ol style="margin:0 0 0 18px; padding:0;">
                    ${(steps.length ? steps : ["Replay the same candidate request and compare the responses."])
                        .map((step) => `<li>${escapeHtml(step)}</li>`)
                        .join("")}
                </ol>
            </div>
            <div class="ui two column stackable grid" style="margin-top:4px;">
                <div class="column">
                    <div class="ui tiny segment">
                        <div class="ui small header" style="margin-bottom:8px;">Request</div>
                        <pre style="white-space:pre-wrap; overflow:auto;">${requestJson}</pre>
                    </div>
                </div>
                <div class="column">
                    <div class="ui tiny segment">
                        <div class="ui small header" style="margin-bottom:8px;">Baseline Response</div>
                        <pre style="white-space:pre-wrap; overflow:auto;">${baselineResponseJson}</pre>
                    </div>
                    <div class="ui tiny segment" style="margin-top:10px;">
                        <div class="ui small header" style="margin-bottom:8px;">Comparison Response</div>
                        <pre style="white-space:pre-wrap; overflow:auto;">${comparisonResponseJson}</pre>
                    </div>
                </div>
            </div>
            <div style="margin-top:10px;">${renderReportDraftPreview(reportDraft)}</div>
        </div>
    `
}

export function renderWorkflowOverlaySummaryHtml(summary = null, {
    showRecordAction = false
} = {}) {
    const hasRecording = !!(
        summary
        && typeof summary === "object"
        && (
            summary.recordingPresent === true
            || Number(summary?.stepCount || 0) > 0
            || (Array.isArray(summary?.steps) && summary.steps.length > 0)
        )
    )
    if (!hasRecording) {
        return `
            <div class="ui tiny info message">
                <div class="header">No workflow recording yet</div>
                <p>Record a macro first if you want workflow-aware replay and overlay hints.</p>
                ${showRecordAction ? '<div style="margin-top:8px;"><button type="button" class="ui tiny basic button" id="analysis_authz_record_workflow">Record Workflow First</button></div>' : ''}
            </div>
        `
    }
    const steps = Array.isArray(summary?.steps) ? summary.steps : []
    const suggestions = Array.isArray(summary?.suggestedOverlays) ? summary.suggestedOverlays : []
    return `
        <div class="ui tiny segment" style="margin-top:8px;">
            <div class="ui small header" style="margin-bottom:8px;">Workflow Overlay Summary</div>
            <div><b>Source:</b> ${escapeHtml(String(summary?.source || "none"))}</div>
            <div style="margin-top:4px;"><b>Recorded Steps:</b> ${escapeHtml(String(summary?.stepCount ?? 0))}</div>
            <div style="margin-top:8px;">
                <b>Step Preview:</b>
                <ul style="margin:6px 0 0 18px; padding:0;">
                    ${steps.length
                        ? steps.slice(0, 5).map((step) => `<li>${escapeHtml(String(step?.label || "Step"))} <span class="ui tiny basic label">${escapeHtml(String(step?.semantic || "interaction"))}</span></li>`).join("")
                        : "<li>No recorded steps available.</li>"}
                </ul>
            </div>
            <div style="margin-top:8px;">
                <b>Suggested Overlays:</b>
                <ul style="margin:6px 0 0 18px; padding:0;">
                    ${suggestions.length
                        ? suggestions.slice(0, 5).map((entry) => `<li>${escapeHtml(entry)}</li>`).join("")
                        : "<li>No overlay suggestions yet.</li>"}
                </ul>
            </div>
        </div>
    `
}

export function renderWorkflowOverlayReplayStatusHtml(result = null) {
    if (!result || typeof result !== "object") {
        return `
            <div class="ui tiny info message">
                <div class="header">No workflow replay yet</div>
                <p>Preview the workflow, then run replay with the active session and optional object swap.</p>
            </div>
        `
    }
    const replayPlanSummary = result?.replayPlan?.summary && typeof result.replayPlan.summary === "object"
        ? result.replayPlan.summary
        : {}
    const success = result?.success !== false
    const color = success ? "teal" : "red"
    const activeSessionLabel = String(
        replayPlanSummary?.activeSessionLabel
        || result?.workflowSummary?.activeSessionLabel
        || result?.replayPlan?.overlay?.activeSession?.label
        || "active session"
    ).trim()
    const error = String(result?.error || "").trim()
    return `
        <div class="ui tiny ${color} message">
            <div class="header">Workflow Replay</div>
            <div style="margin-top:6px;">
                <span class="ui tiny ${color} label">${success ? "Started" : "Failed"}</span>
                ${activeSessionLabel ? `<span class="ui tiny basic label">${escapeHtml(activeSessionLabel)}</span>` : ""}
                ${replayPlanSummary?.source ? `<span class="ui tiny basic label">${escapeHtml(String(replayPlanSummary.source))}</span>` : ""}
            </div>
            <div style="margin-top:8px;">
                <div><b>Start URL:</b> ${escapeHtml(String(replayPlanSummary?.startUrl || "unknown"))}</div>
                <div style="margin-top:4px;"><b>Steps:</b> ${escapeHtml(String(replayPlanSummary?.stepCount ?? 0))}</div>
                <div style="margin-top:4px;"><b>Overlayed:</b> ${escapeHtml(String(replayPlanSummary?.overlayedStepCount ?? 0))}</div>
                <div style="margin-top:4px;"><b>Skipped:</b> ${escapeHtml(String(replayPlanSummary?.skippedStepCount ?? 0))}</div>
            </div>
            ${error ? `<div style="margin-top:8px;" class="ui tiny red text">${escapeHtml(error)}</div>` : ""}
        </div>
    `
}

export { renderReportDraftPreview }

export default {
    extractComparableResponseFromRun,
    renderSessionProfileOptions,
    renderSessionProfileListHtml,
    renderAuthzDiffResultHtml,
    renderAuthzDiffRunStatusHtml,
    renderEvidencePackageListHtml,
    renderEvidencePackageDetailHtml,
    renderWorkflowOverlayReplayStatusHtml
}
