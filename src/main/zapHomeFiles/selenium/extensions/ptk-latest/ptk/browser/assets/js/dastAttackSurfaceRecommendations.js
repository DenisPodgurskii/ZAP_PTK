function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
}

function formatConfidence(value) {
    const normalized = String(value || 'low').toLowerCase()
    if (normalized === 'high') return 'High'
    if (normalized === 'medium') return 'Medium'
    return 'Low'
}

function formatModuleTier(tier) {
    const normalized = String(tier || '').toLowerCase()
    if (normalized === 'free') return 'Available'
    if (normalized === 'pro') return 'Pro'
    if (normalized === 'cve') return 'CVE'
    return 'Module'
}

function formatActionStatus(status) {
    const normalized = String(status || '').toLowerCase()
    if (normalized === 'available') return 'Available'
    if (normalized === 'locked') return 'Locked'
    return 'Coming soon'
}

function buildEngineBadgesHtml(recommendation = {}) {
    const engines = Array.from(new Set([
        ...(Array.isArray(recommendation.sourceEngines) ? recommendation.sourceEngines : []),
        ...(Array.isArray(recommendation.evidenceSummary?.sourceEngines) ? recommendation.evidenceSummary.sourceEngines : [])
    ]))
        .map((engine) => String(engine || '').trim().toUpperCase())
        .filter(Boolean)
        .slice(0, 4)
    if (!engines.length) return ''
    return `
        <div style="display:flex; flex-wrap:wrap; gap:4px; margin-top:6px;">
            ${engines.map((engine) => `<span class="ui tiny blue label">${escapeHtml(engine)}</span>`).join('')}
        </div>
    `
}

function buildEvidenceSummaryBlockHtml(recommendation = {}) {
    const summary = recommendation.evidenceSummary && typeof recommendation.evidenceSummary === 'object'
        ? recommendation.evidenceSummary
        : {}
    const observations = Array.isArray(summary.observations) ? summary.observations : []
    const method = summary.method || (recommendation.routeKey ? String(recommendation.routeKey).split('|')[1] : null)
    const path = summary.path || (recommendation.routeKey ? String(recommendation.routeKey).split('|')[2] : null)
    const param = summary.paramKey || recommendation.paramKey || null
    return `
        <div style="margin-top:6px;">
            <b>Observed evidence:</b>
            <div style="margin-top:4px;">
                ${method || path ? `<div><b>Target:</b> <code>${escapeHtml([method, path].filter(Boolean).join(' '))}</code></div>` : ''}
                ${param ? `<div><b>Input:</b> <code>${escapeHtml(param)}</code></div>` : ''}
                ${buildEngineBadgesHtml(recommendation)}
                ${observations.length ? `<ul style="margin:6px 0 0 18px;">${observations.slice(0, 5).map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : ''}
            </div>
        </div>
    `
}

function buildGuidanceHtml(guidance = []) {
    const items = (Array.isArray(guidance) ? guidance : [])
        .map((item) => String(item || '').trim())
        .filter(Boolean)
        .slice(0, 3)
    if (!items.length) return ''
    return `
        <div style="margin-top:6px;">
            <b>Manual next steps:</b>
            <ul style="margin:4px 0 0 18px;">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
        </div>
    `
}

function buildMatchedModulesHtml(modules = []) {
    const items = (Array.isArray(modules) ? modules : []).slice(0, 3)
    if (!items.length) return ''
    return `
        <div style="margin-top:8px;">
            <b>Relevant modules:</b>
            <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;">
                ${items.map((moduleDef) => `
                    <span class="ui tiny label" title="${escapeHtml(moduleDef?.description || moduleDef?.recommendationSummary || '')}">
                        ${moduleDef?.engine ? `<span class="detail">${escapeHtml(String(moduleDef.engine).toUpperCase())}</span>` : ''}
                        ${escapeHtml(moduleDef?.name || moduleDef?.moduleId || 'Module')}
                        <span class="detail">${escapeHtml(formatModuleTier(moduleDef?.tier))}</span>
                    </span>
                `).join('')}
            </div>
        </div>
    `
}

function buildActionsHtml(actions = []) {
    const items = (Array.isArray(actions) ? actions : []).slice(0, 3)
    if (!items.length) return ''
    return `
        <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:8px;">
            ${items.map((action) => `
                <button type="button" class="ui tiny basic disabled button" disabled>
                    ${escapeHtml(action?.label || 'Workflow')}
                    <span style="opacity:.72;">(${escapeHtml(formatActionStatus(action?.status))})</span>
                </button>
            `).join('')}
        </div>
    `
}

function buildEvidenceSummaryHtml(recommendation = {}) {
    const refs = Array.isArray(recommendation.evidenceRefs) ? recommendation.evidenceRefs : []
    if (!refs.length) return ''
    const summary = refs.slice(0, 4).map((ref) => {
        const type = String(ref?.type || 'evidence')
        const id = String(ref?.id || '').trim()
        const loc = ref?.loc && typeof ref.loc === 'object'
            ? Object.entries(ref.loc)
                .map(([key, value]) => `${key}: ${value}`)
                .join(', ')
            : ''
        return [type, id, loc].filter(Boolean).join(' | ')
    })
    return `
        <details style="margin-top:8px;">
            <summary>Evidence (${refs.length})</summary>
            <ul style="margin:4px 0 0 18px;">
                ${summary.map((item) => `<li><code>${escapeHtml(item)}</code></li>`).join('')}
            </ul>
        </details>
    `
}

function buildRecommendationCardHtml(recommendation = {}, index = 0) {
    const priority = Number.isFinite(Number(recommendation.priority)) ? Number(recommendation.priority) : 0
    return `
        <div class="ui message attack_info nonvuln">
            <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:8px; margin-bottom:6px;">
                <div><b>${index + 1}. ${escapeHtml(recommendation.title || 'Recommended attack path')}</b></div>
                <span style="margin-left:auto; white-space:nowrap; display:inline-flex; align-items:center; gap:6px;">
                    <span class="ui tiny label">${escapeHtml(formatConfidence(recommendation.confidence))}</span>
                    <span class="ui tiny grey label">Priority ${escapeHtml(priority)}</span>
                </span>
            </div>
            <div class="description">
                ${buildEvidenceSummaryBlockHtml(recommendation)}
                ${buildGuidanceHtml(recommendation.freeGuidance)}
                ${buildMatchedModulesHtml(recommendation.matchedModules)}
                ${buildActionsHtml(recommendation.proActions)}
                ${buildEvidenceSummaryHtml(recommendation)}
            </div>
        </div>
    `
}

export function renderAttackSurfaceRecommendationsHtml(recommendations = [], {
    proUiVisible = false,
    limit = 5
} = {}) {
    if (!proUiVisible) return ''
    const items = (Array.isArray(recommendations) ? recommendations : [])
        .filter((recommendation) => recommendation && typeof recommendation === 'object')
        .slice(0, Math.max(1, Number(limit) || 5))
    if (!items.length) return ''
    return `
        <div class="ui message">
            <div><b>Attack paths:</b> ${items.length} shown${recommendations.length > items.length ? ` of ${recommendations.length}` : ''}</div>
            <div style="margin-top:4px;">Prioritized manual paths from observed DAST, IAST, and SAST evidence.</div>
        </div>
        ${items.map((recommendation, index) => buildRecommendationCardHtml(recommendation, index)).join('')}
    `
}

export default renderAttackSurfaceRecommendationsHtml
