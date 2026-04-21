import { normalizeCwe, normalizeOwasp, toLegacyOwaspString } from "../../../background/common/normalizeMappings.js";

function formatIastSeverityLabel(value) {
    if (!value) return 'info'
    const lower = String(value).trim().toLowerCase()
    if (lower === 'critical') return 'critical'
    if (lower === 'high') return 'high'
    if (lower === 'medium') return 'medium'
    if (lower === 'low') return 'low'
    return 'info'
}

function mergeLinkMaps(...sources) {
    const out = {}
    sources.forEach(src => {
        if (!src || typeof src !== 'object') return
        Object.entries(src).forEach(([key, value]) => {
            if (!key || value === undefined || value === null) return
            out[key] = value
        })
    })
    return out
}

function extractPrimaryIastEvidence(finding) {
    if (!finding) return null
    const evidence = finding.evidence
    if (!evidence) return null
    if (typeof evidence === 'object' && !Array.isArray(evidence)) {
        if (evidence.iast && typeof evidence.iast === 'object') return evidence.iast
        if (evidence.IAST && typeof evidence.IAST === 'object') return evidence.IAST
        return evidence
    }
    if (Array.isArray(evidence) && evidence.length) {
        const entry = evidence.find(ev => {
            const src = String(ev?.source || ev?.type || '').toLowerCase()
            return src === 'iast'
        })
        return entry || evidence[0] || null
    }
    return null
}

export function convertLegacyIastVulnToFinding(vuln, index = 0) {
    if (!vuln) return null
    const owasp = normalizeOwasp(vuln.owasp)
    const cwe = normalizeCwe(vuln.cwe)
    const owaspPrimary = owasp.length ? owasp[0] : null
    const owaspLegacy = toLegacyOwaspString(owasp)
    return {
        id: vuln.id || `vuln-${index}`,
        ruleId: vuln.ruleId || vuln.id || vuln.category || `vuln-${index}`,
        ruleName: vuln.ruleName || vuln.category || `Vulnerability ${index + 1}`,
        moduleId: vuln.moduleId || null,
        moduleName: vuln.moduleName || null,
        category: vuln.category || null,
        severity: vuln.severity || 'medium',
        owasp,
        owaspPrimary,
        owaspLegacy,
        cwe,
        tags: vuln.tags || [],
        location: { url: vuln.url || null, method: vuln.method || null },
        affectedUrls: vuln.url ? [vuln.url] : [],
        evidence: {
            iast: {
                taintSource: vuln.taintSource || null,
                sinkId: vuln.sink || null,
                context: {},
                matched: null,
                trace: []
            }
        }
    }
}

export function buildIastItemFromFinding(finding, index = 0) {
    if (!finding) return null
    const loc = finding.location || {}
    const evidenceEntry = extractPrimaryIastEvidence(finding)
    const ev = evidenceEntry || {}
    const severity = formatIastSeverityLabel(finding.severity || 'info')
    const metaRule =
        finding.ruleName
        || finding.metadata?.name
        || finding.module_metadata?.name
        || finding.moduleName
        || ev.message
        || finding.category
        || finding.ruleId
        || finding.id
        || `Finding ${index + 1}`
    const taintSource = ev.taintSource || finding.taintSource || finding.source || null
    const sinkId = ev.sinkId || finding.sinkId || finding.sink || null
    const baseContext = Object.assign({}, ev.context || {}, finding.context || {})
    const flow = Array.isArray(baseContext.flow) ? baseContext.flow : []
    const tracePayload = ev.trace || baseContext.trace || finding.trace || null
    const description = finding.description || finding.metadata?.description || ev.message || ''
    const recommendation = finding.recommendation || finding.metadata?.recommendation || ''
    const links = mergeLinkMaps(
        finding.links,
        finding.metadata?.links,
        finding.module_metadata?.links
    )
    const contextPayload = Object.assign(
        {
            flow,
            domPath: baseContext.domPath || ev.domPath || loc.domPath || null,
            elementOuterHTML: baseContext.elementOuterHTML || ev.elementOuterHTML || null,
            value: baseContext.value || ev.value || null,
            url: baseContext.url || loc.url || null,
            elementId: baseContext.elementId || loc.elementId || null,
            tagName: baseContext.tagName || ev.tagName || null
        },
        baseContext
    )
    const owaspArray = Array.isArray(finding.owasp) ? finding.owasp : []
    const owaspPrimary = finding.owaspPrimary || (owaspArray.length ? owaspArray[0] : null)
    const owaspLegacy = finding.owaspLegacy || toLegacyOwaspString(owaspArray)
    const normalizedEvidenceEntry = {
        source: 'IAST',
        taintSource,
        sinkId,
        schemaVersion: ev.schemaVersion || null,
        primaryClass: ev.primaryClass || null,
        sourceRole: ev.sourceRole || null,
        origin: ev.origin || null,
        observedAt: ev.observedAt || null,
        operation: ev.operation || null,
        detection: ev.detection || null,
        routing: ev.routing || null,
        context: contextPayload,
        matched: ev.matched || finding.matched || null,
        trace: tracePayload,
        traceSummary: ev.traceSummary || null,
        flowSummary: ev.flowSummary || null,
        sourceKind: ev.sourceKind || null,
        sourceKey: ev.sourceKey || null,
        sourceValuePreview: ev.sourceValuePreview || null,
        sources: ev.sources || null,
        primarySource: ev.primarySource || null,
        secondarySources: ev.secondarySources || null,
        sinkContext: ev.sinkContext || null,
        sinkSummary: ev.sinkSummary || finding.sinkSummary || null,
        taintSummary: ev.taintSummary || finding.taintSummary || null,
        allowedSources: ev.allowedSources || finding.allowedSources || null,
        raw: {
            severity,
            meta: { ruleName: metaRule },
            sinkId,
            source: taintSource,
            type: finding.category || null,
            owasp: owaspArray,
            cwe: Array.isArray(finding.cwe) ? finding.cwe : [],
            tags: finding.tags || [],
            location: loc,
            context: contextPayload
        }
    }
    const affectedUrls = []
    const seenUrls = new Set()
    const addUrl = (value, { prepend = false } = {}) => {
        if (!value) return
        const str = String(value).trim()
        if (!str || seenUrls.has(str)) return
        seenUrls.add(str)
        if (prepend) {
            affectedUrls.unshift(str)
        } else {
            affectedUrls.push(str)
        }
    }
    addUrl(loc.url, { prepend: true })
    if (Array.isArray(ev.affectedUrls)) {
        ev.affectedUrls.forEach(url => addUrl(url))
    }
    if (Array.isArray(finding.affectedUrls)) {
        finding.affectedUrls.forEach(url => addUrl(url))
    }
    addUrl(ev?.context?.url)
    addUrl(ev?.context?.location)
    return {
        id: finding.id || `iast-${index}`,
        ruleId: finding.ruleId || finding.id || `rule-${index}`,
        ruleName: metaRule,
        severity,
        category: finding.category || null,
        confidence: Number.isFinite(finding.confidence) ? finding.confidence : null,
        owasp: owaspArray,
        owaspPrimary,
        owaspLegacy,
        cwe: Array.isArray(finding.cwe) ? finding.cwe : [],
        tags: finding.tags || [],
        location: loc,
        affectedUrls: affectedUrls.filter(Boolean),
        evidence: [normalizedEvidenceEntry],
        context: contextPayload,
        trace: tracePayload,
        description,
        recommendation,
        links,
        metadata: {
            id: finding.ruleId || finding.id || `rule-${index}`,
            name: metaRule,
            severity,
            description,
            recommendation,
            links
        },
        module_metadata: {
            id: finding.module_metadata?.id || finding.moduleId || null,
            name: finding.module_metadata?.name || finding.moduleName || null,
            links: finding.module_metadata?.links || links
        },
        requestId: index,
        __index: index,
        type: 'iast',
        source: taintSource,
        sink: sinkId
    }
}
