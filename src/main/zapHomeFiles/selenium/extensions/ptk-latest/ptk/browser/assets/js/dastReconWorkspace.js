function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
}

function humanizeToken(value, fallback = "Unknown") {
    const raw = String(value || "").trim()
    if (!raw) return fallback
    return raw
        .replace(/[_-]+/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .replace(/\b\w/g, (char) => char.toUpperCase())
}

function uniqueSorted(values = []) {
    return Array.from(new Set((Array.isArray(values) ? values : []).map((value) => String(value || "").trim()).filter(Boolean)))
        .sort((a, b) => a.localeCompare(b))
}

function renderEvidenceRefs(refs = []) {
    if (!Array.isArray(refs) || !refs.length) {
        return '<div class="ui tiny grey text" style="margin-top:6px;">No evidence refs attached yet.</div>'
    }
    const visible = refs.slice(0, 4)
    const overflow = refs.length - visible.length
    const items = visible.map((ref) => {
        const type = escapeHtml(ref?.type || "evidence")
        const id = escapeHtml(ref?.id || "n/a")
        return `<span class="ui tiny basic label">${type}:${id}</span>`
    }).join(" ")
    const suffix = overflow > 0 ? ` <span class="ui tiny grey text">+${overflow} more</span>` : ""
    return `<div style="margin-top:6px;"><b>Evidence:</b> ${items}${suffix}</div>`
}

function renderSuggestedChecks(checks = []) {
    if (!Array.isArray(checks) || !checks.length) {
        return '<div class="ui tiny grey text" style="margin-top:6px;">No suggested checks yet.</div>'
    }
    return `
        <div style="margin-top:6px;">
            <b>Suggested checks:</b>
            ${checks.map((check) => `<span class="ui tiny label">${escapeHtml(humanizeToken(check, "Check"))}</span>`).join(" ")}
        </div>
    `
}

function renderEmptySection(header, detail) {
    return `
        <div class="ui info message">
            <div class="header">${escapeHtml(header)}</div>
            <p>${escapeHtml(detail)}</p>
        </div>
    `
}

function splitRouteKey(routeKey = "unknown-host|GET|/") {
    const [hostRaw = "", methodRaw = "GET", pathRaw = "/"] = String(routeKey || "").split("|")
    return {
        host: hostRaw || "unknown-host",
        method: methodRaw || "GET",
        path: pathRaw || "/"
    }
}

function extractParamName(paramKey = "") {
    const raw = String(paramKey || "").trim()
    if (!raw) return null
    const splitIdx = raw.indexOf(":")
    if (splitIdx < 0) return raw
    const value = raw.slice(splitIdx + 1).trim()
    if (!value || value === "<none>") return null
    return value
}

function mergeEvidenceRefs(target = [], refs = []) {
    const seen = new Set(target.map((ref) => `${ref?.type || ""}:${ref?.id || ""}`))
    ;(Array.isArray(refs) ? refs : []).forEach((ref) => {
        const key = `${ref?.type || ""}:${ref?.id || ""}`
        if (!key || seen.has(key)) return
        seen.add(key)
        target.push(ref)
    })
    return target
}

function createRouteHotspot(routeKey = "unknown-host|GET|/") {
    const route = splitRouteKey(routeKey)
    return {
        routeKey,
        host: route.host,
        method: route.method,
        path: route.path,
        itemCount: 0,
        opportunityCount: 0,
        maxPriority: 0,
        sources: new Set(),
        signalTypes: new Set(),
        params: new Set(),
        suggestedChecks: new Set(),
        evidenceRefs: [],
        suppressKey: `route:${routeKey}`
    }
}

function buildRouteHotspots(analysis = {}, { suppressedKeys = [] } = {}) {
    const items = Array.isArray(analysis?.attackMap?.items) ? analysis.attackMap.items : []
    const opportunities = Array.isArray(analysis?.opportunities) ? analysis.opportunities : []
    const suppressedKeySet = new Set((Array.isArray(suppressedKeys) ? suppressedKeys : []).map((entry) => String(entry || "").trim()).filter(Boolean))
    const hotspots = new Map()

    const ensureHotspot = (routeKey) => {
        const key = String(routeKey || "unknown-host|GET|/").trim() || "unknown-host|GET|/"
        if (!hotspots.has(key)) {
            hotspots.set(key, createRouteHotspot(key))
        }
        return hotspots.get(key)
    }

    items.forEach((entry) => {
        const hotspot = ensureHotspot(entry?.routeKey)
        hotspot.itemCount += 1
        hotspot.maxPriority = Math.max(hotspot.maxPriority, Number(entry?.priority || 0))
        hotspot.sources.add(String(entry?.source || "analysis"))
        hotspot.signalTypes.add(String(entry?.itemType || "lead"))
        const paramName = extractParamName(entry?.paramKey)
        if (paramName) hotspot.params.add(paramName)
        ;(Array.isArray(entry?.suggestedChecks) ? entry.suggestedChecks : []).forEach((check) => hotspot.suggestedChecks.add(String(check || "").trim()))
        mergeEvidenceRefs(hotspot.evidenceRefs, entry?.evidenceRefs)
    })

    opportunities.forEach((entry) => {
        const hotspot = ensureHotspot(entry?.routeKey)
        hotspot.opportunityCount += 1
        hotspot.maxPriority = Math.max(hotspot.maxPriority, Number(entry?.priority || 0))
        hotspot.sources.add(String(entry?.source || "analysis"))
        hotspot.signalTypes.add(String(entry?.type || "opportunity"))
        const paramName = extractParamName(entry?.paramKey)
        if (paramName) hotspot.params.add(paramName)
        ;(Array.isArray(entry?.suggestedChecks) ? entry.suggestedChecks : []).forEach((check) => hotspot.suggestedChecks.add(String(check || "").trim()))
        mergeEvidenceRefs(hotspot.evidenceRefs, entry?.evidenceRefs)
    })

    return Array.from(hotspots.values())
        .map((entry) => ({
            ...entry,
            sources: uniqueSorted(Array.from(entry.sources)),
            signalTypes: uniqueSorted(Array.from(entry.signalTypes)),
            params: uniqueSorted(Array.from(entry.params)),
            suggestedChecks: uniqueSorted(Array.from(entry.suggestedChecks)),
            evidenceRefs: entry.evidenceRefs.slice(0, 8),
            suppressed: suppressedKeySet.has(entry.suppressKey)
        }))
        .sort((left, right) => {
            if (left.suppressed !== right.suppressed) {
                return left.suppressed ? 1 : -1
            }
            if (right.maxPriority !== left.maxPriority) {
                return right.maxPriority - left.maxPriority
            }
            return `${left.method}|${left.path}`.localeCompare(`${right.method}|${right.path}`)
        })
}

function buildCheckQueue(routeHotspots = []) {
    const queue = new Map()
    routeHotspots
        .filter((entry) => !entry.suppressed)
        .forEach((entry) => {
            ;(Array.isArray(entry.suggestedChecks) ? entry.suggestedChecks : []).forEach((check) => {
                const key = String(check || "").trim()
                if (!key) return
                if (!queue.has(key)) {
                    queue.set(key, {
                        id: key,
                        routeKeys: new Set(),
                        paths: new Set(),
                        maxPriority: 0,
                        leadCount: 0
                    })
                }
                const item = queue.get(key)
                item.routeKeys.add(entry.routeKey)
                item.paths.add(`${entry.method} ${entry.path}`)
                item.maxPriority = Math.max(item.maxPriority, Number(entry.maxPriority || 0))
                item.leadCount += Number(entry.itemCount || 0) + Number(entry.opportunityCount || 0)
            })
        })

    return Array.from(queue.values())
        .map((entry) => ({
            ...entry,
            routes: uniqueSorted(Array.from(entry.paths))
        }))
        .sort((left, right) => {
            if (right.maxPriority !== left.maxPriority) return right.maxPriority - left.maxPriority
            if (right.routeKeys.size !== left.routeKeys.size) return right.routeKeys.size - left.routeKeys.size
            return left.id.localeCompare(right.id)
        })
}

function renderRouteHotspots(routeHotspots = [], { allowSuppression = false } = {}) {
    if (!routeHotspots.length) {
        return renderEmptySection("No route hotspots yet", "Recon hotspots appear when analysis identifies interesting routes, objects, or authz-style leads.")
    }
    return routeHotspots
        .map((entry, index) => {
            const title = `${escapeHtml(entry.method)} <code>${escapeHtml(entry.path)}</code>`
            const sourceHtml = entry.sources.length
                ? entry.sources.map((source) => `<span class="ui tiny basic label">${escapeHtml(humanizeToken(source, "Source"))}</span>`).join(" ")
                : '<span class="ui tiny grey text">No source tags.</span>'
            const signalHtml = entry.signalTypes.length
                ? entry.signalTypes.slice(0, 6).map((signal) => `<span class="ui tiny basic label">${escapeHtml(humanizeToken(signal, "Signal"))}</span>`).join(" ")
                : '<span class="ui tiny grey text">No signals recorded.</span>'
            const paramHtml = entry.params.length
                ? entry.params.slice(0, 8).map((param) => `<span class="ui tiny label">${escapeHtml(param)}</span>`).join(" ")
                : '<span class="ui tiny grey text">No obvious object or control parameters.</span>'
            const suppressionLabel = entry.suppressed
                ? '<span class="ui tiny grey label">Suppressed from recon queue</span>'
                : ''
            const suppressionButton = allowSuppression
                ? `
                    <button type="button" class="ui tiny basic button toggle_recon_route_suppression" data-route-key="${escapeHtml(entry.routeKey)}" data-suppressed="${entry.suppressed ? "1" : "0"}">
                        ${entry.suppressed ? "Restore Route" : "Exclude Route"}
                    </button>
                `
                : ''
            return `
                <div class="ui segment" style="margin-top:8px; ${entry.suppressed ? "opacity:0.68;" : ""}">
                    <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:8px;">
                        <div>
                            <b>${index + 1}. ${title}</b>
                            <div class="ui tiny grey text" style="margin-top:4px;"><code>${escapeHtml(entry.routeKey)}</code></div>
                        </div>
                        <span style="margin-left:auto; white-space:nowrap; display:inline-flex; align-items:center; gap:6px;">
                            ${suppressionLabel}
                            <span class="ui tiny teal label">Leads ${Number(entry.itemCount || 0) + Number(entry.opportunityCount || 0)}</span>
                            <span class="ui tiny basic label">Opportunities ${Number(entry.opportunityCount || 0)}</span>
                            <span class="ui tiny olive label">Priority ${Number(entry.maxPriority || 0)}</span>
                        </span>
                    </div>
                    <div style="margin-top:8px;"><b>Sources:</b> ${sourceHtml}</div>
                    <div style="margin-top:6px;"><b>Signals:</b> ${signalHtml}</div>
                    <div style="margin-top:6px;"><b>Parameters to review:</b> ${paramHtml}</div>
                    ${renderSuggestedChecks(entry?.suggestedChecks)}
                    ${renderEvidenceRefs(entry?.evidenceRefs)}
                    ${suppressionButton ? `<div style="margin-top:8px;">${suppressionButton}</div>` : ""}
                </div>
            `
        })
        .join("")
}

function renderCheckQueue(entries = []) {
    if (!entries.length) {
        return renderEmptySection("No follow-up queue yet", "Suggested checks will appear after recon hotspots are derived from analysis.")
    }
    return entries
        .map((entry, index) => {
            const routes = Array.isArray(entry?.routes) ? entry.routes : []
            const routeList = routes.length
                ? routes.slice(0, 4).map((route) => `<div><code>${escapeHtml(route)}</code></div>`).join("")
                : '<div class="ui tiny grey text">No routes attached.</div>'
            return `
                <div class="ui segment" style="margin-top:8px;">
                    <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:8px; margin-bottom:6px;">
                        <div><b>${index + 1}. ${escapeHtml(humanizeToken(entry?.id, "Check"))}</b></div>
                        <span style="margin-left:auto; white-space:nowrap; display:inline-flex; align-items:center; gap:6px;">
                            <span class="ui tiny basic label">Routes ${entry?.routeKeys?.size || 0}</span>
                            <span class="ui tiny teal label">Leads ${Number(entry?.leadCount || 0)}</span>
                            <span class="ui tiny olive label">Priority ${Number(entry?.maxPriority || 0)}</span>
                        </span>
                    </div>
                    <div class="ui tiny grey text">Use this queue for manual authz, object swap, and replay follow-up once session diff lands.</div>
                    <div style="margin-top:6px;"><b>Top routes:</b></div>
                    <div style="margin-top:4px;">${routeList}</div>
                </div>
            `
        })
        .join("")
}

function renderObjectInventory(identifiers = []) {
    if (!identifiers.length) {
        return renderEmptySection("No object inventory yet", "Identifiers and object references observed during the scan will appear here.")
    }
    return [...identifiers]
        .sort((left, right) => {
            const leftHits = Number(left?.hits || 0)
            const rightHits = Number(right?.hits || 0)
            if (rightHits !== leftHits) return rightHits - leftHits
            return String(left?.name || left?.id || "").localeCompare(String(right?.name || right?.id || ""))
        })
        .map((entry, index) => {
            const name = escapeHtml(entry?.name || entry?.id || "Identifier")
            const kind = escapeHtml(humanizeToken(entry?.kind, "Identifier"))
            const hits = Number(entry?.hits || 0)
            const routes = Array.isArray(entry?.routeKeys) ? entry.routeKeys : []
            const sources = Array.isArray(entry?.sources) ? entry.sources : []
            const routeHtml = routes.length
                ? routes.slice(0, 4).map((route) => `<div><code>${escapeHtml(route)}</code></div>`).join("")
                : '<div class="ui tiny grey text">No routes recorded.</div>'
            const sourceHtml = sources.length
                ? sources.map((source) => `<span class="ui tiny basic label">${escapeHtml(humanizeToken(source, "Source"))}</span>`).join(" ")
                : '<span class="ui tiny grey text">No sources recorded.</span>'
            return `
                <div class="ui segment" style="margin-top:8px;">
                    <div style="display:flex; align-items:flex-start; justify-content:space-between; gap:8px;">
                        <div><b>${index + 1}. ${name}</b></div>
                        <span style="margin-left:auto; white-space:nowrap; display:inline-flex; align-items:center; gap:6px;">
                            <span class="ui tiny basic label">${kind}</span>
                            <span class="ui tiny olive label">Hits ${hits}</span>
                        </span>
                    </div>
                    <div style="margin-top:6px;"><b>Sources:</b> ${sourceHtml}</div>
                    <div style="margin-top:6px;"><b>Routes:</b></div>
                    <div style="margin-top:4px;">${routeHtml}</div>
                    ${renderEvidenceRefs(entry?.evidenceRefs)}
                </div>
            `
        })
        .join("")
}

export function renderReconWorkspaceHtml(analysis = {}, opts = {}) {
    const attackMap = analysis?.attackMap && typeof analysis.attackMap === "object" ? analysis.attackMap : { total: 0, items: [] }
    const objectInventory = analysis?.objectInventory && typeof analysis.objectInventory === "object" ? analysis.objectInventory : { total: 0, identifiers: [] }
    const opportunities = Array.isArray(analysis?.opportunities) ? analysis.opportunities : []
    const attackMapItems = Array.isArray(attackMap.items) ? attackMap.items : []
    const inventoryIdentifiers = Array.isArray(objectInventory.identifiers) ? objectInventory.identifiers : []
    const routeHotspots = buildRouteHotspots(analysis, {
        suppressedKeys: Array.isArray(opts?.suppressedKeys) ? opts.suppressedKeys : []
    })
    const activeRouteHotspots = routeHotspots.filter((entry) => !entry.suppressed)
    const suppressedCount = routeHotspots.length - activeRouteHotspots.length
    const checkQueue = buildCheckQueue(routeHotspots)

    return `
        <div class="ui message">
            <div><b>Recon workspace:</b> route and object hotspot map derived from recon observations and current scan analysis.</div>
            <div><b>Opportunities:</b> ${opportunities.length}</div>
            <div><b>Route hotspots:</b> ${activeRouteHotspots.length}${suppressedCount > 0 ? ` (${suppressedCount} suppressed)` : ""}</div>
            <div><b>Attack map items:</b> ${Number(attackMap.total || attackMapItems.length)}</div>
            <div><b>Object identifiers:</b> ${Number(objectInventory.total || inventoryIdentifiers.length)}</div>
        </div>
        <div class="ui small header">Route Hotspots</div>
        ${renderRouteHotspots(routeHotspots, { allowSuppression: opts?.allowSuppression === true })}
        <div class="ui small header" style="margin-top:12px;">Follow-Up Queue</div>
        ${renderCheckQueue(checkQueue)}
        <div class="ui small header" style="margin-top:12px;">Object Inventory</div>
        ${renderObjectInventory(inventoryIdentifiers)}
    `
}
