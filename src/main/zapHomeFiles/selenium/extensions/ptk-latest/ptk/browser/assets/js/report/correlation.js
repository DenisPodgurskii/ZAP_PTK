const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

function severityRank(severity) {
    const normalized = String(severity || "").toLowerCase()
    const idx = SEVERITY_ORDER.indexOf(normalized)
    return idx === -1 ? SEVERITY_ORDER.length : idx
}

function normalizeTitle(value) {
    if (!value) return "finding"
    return String(value).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "")
}

function normalizeAssetKey(raw) {
    if (!raw) return "unknown"
    try {
        const url = new URL(String(raw))
        return `${url.origin}${url.pathname}`.toLowerCase()
    } catch (_) {
        const str = String(raw)
        return str.split("?")[0].split("#")[0].toLowerCase()
    }
}

function resolvePrimaryKey(finding) {
    const cwe = Array.isArray(finding?.cwe) && finding.cwe.length ? finding.cwe[0] : null
    const owasp = Array.isArray(finding?.owasp) && finding.owasp.length
        ? (typeof finding.owasp[0] === "string" ? finding.owasp[0] : finding.owasp[0]?.id || finding.owasp[0]?.name)
        : null
    return finding?.vulnId || cwe || owasp || normalizeTitle(finding?.title || finding?.ruleName || "finding")
}

function resolveConfidence(finding) {
    const candidates = [
        finding?.confidence_score,
        finding?.confidence,
        finding?.metadata?.confidence
    ]
    for (const value of candidates) {
        const num = Number(value)
        if (Number.isFinite(num)) return num
    }
    return null
}

export function getCorrelationKey(finding) {
    const primaryKey = resolvePrimaryKey(finding)
    const assetKey = normalizeAssetKey(finding?.location?.url || finding?.location?.route || finding?.location?.file || "")
    return `${primaryKey}::${assetKey}`
}

export function buildCorrelationGroups(findings = []) {
    const map = new Map()
    findings.forEach(finding => {
        if (!finding) return
        const primaryKey = resolvePrimaryKey(finding)
        const groupKey = getCorrelationKey(finding)
        if (!map.has(groupKey)) {
            map.set(groupKey, {
                key: groupKey,
                title: finding?.title || finding?.ruleName || primaryKey,
                engines: new Set(),
                maxSeverity: finding?.severity || "info",
                combinedConfidence: resolveConfidence(finding),
                affectedAssetsCount: 0,
                sampleUrls: new Set(),
                topFindingIds: [],
                instances: []
            })
        }
        const group = map.get(groupKey)
        group.engines.add(String(finding?.engine || "UNKNOWN"))
        if (severityRank(finding?.severity) < severityRank(group.maxSeverity)) {
            group.maxSeverity = finding?.severity || group.maxSeverity
        }
        const conf = resolveConfidence(finding)
        if (conf !== null && (group.combinedConfidence === null || conf > group.combinedConfidence)) {
            group.combinedConfidence = conf
        }
        const url = finding?.location?.url || finding?.location?.route || finding?.location?.file || ""
        if (url) group.sampleUrls.add(String(url))
        if (finding?.findingId && !group.topFindingIds.includes(finding.findingId)) {
            group.topFindingIds.push(finding.findingId)
        }
        group.instances.push(finding)
    })

    const results = Array.from(map.values()).map(group => {
        const engines = Array.from(group.engines)
        let combinedConfidence = group.combinedConfidence
        if (combinedConfidence === null) combinedConfidence = 0
        if (engines.length >= 2) combinedConfidence = Math.min(100, combinedConfidence + 5)
        const hasDastOrIast = engines.includes("DAST") || engines.includes("IAST")
        const hasSast = engines.includes("SAST")
        if (hasDastOrIast && hasSast) combinedConfidence = Math.min(100, combinedConfidence + 5)
        return {
            key: group.key,
            title: group.title,
            engines,
            maxSeverity: group.maxSeverity,
            combinedConfidence,
            affectedAssetsCount: 1,
            sampleUrls: Array.from(group.sampleUrls).slice(0, 3),
            topFindingIds: group.topFindingIds.slice(0, 5),
            instances: group.instances
        }
    }).filter(group => group.engines.length >= 2)
    return results.sort((a, b) => severityRank(a.maxSeverity) - severityRank(b.maxSeverity))
}
