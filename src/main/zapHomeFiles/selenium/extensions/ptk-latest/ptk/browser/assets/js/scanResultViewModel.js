/**
 * Infer engine from legacy result.type.
 */
import { normalizeCwe, normalizeOwasp, toLegacyOwaspString } from "../../../background/common/normalizeMappings.js"
import { normalizeFinding as normalizeFindingShape } from "./findingNormalizer.js"

function inferEngineFromType(type) {
    if (!type) return null
    const t = String(type).toLowerCase()
    if (t === "dast") return "DAST"
    if (t === "sast") return "SAST"
    if (t === "iast") return "IAST"
    return null
}

/**
 * Normalize stats object to always have severity counters.
 */
function normalizeStats(stats = {}) {
    return {
        findingsCount: stats.findingsCount || 0,
        critical: stats.critical || 0,
        high: stats.high || 0,
        medium: stats.medium || 0,
        low: stats.low || 0,
        info: stats.info || 0,
        ...stats
    }
}

/**
 * Normalize finding object.
 */
function normalizeFinding(f) {
    if (!f || typeof f !== "object") return f
    const base = normalizeFindingShape({ ...f }, { engine: f.engine })
    const loc = base.location || {}
    const engine = (base.engine || "").toUpperCase()
    const iastEvidence = engine === "IAST" && base.evidence && typeof base.evidence === "object"
        ? base.evidence.iast || null
        : null
    const normalizedOwasp = normalizeOwasp(base.owasp)
    const normalizedCwe = normalizeCwe(base.cwe)
    const owaspPrimary = normalizedOwasp.length ? normalizedOwasp[0] : null
    const owaspLegacy = toLegacyOwaspString(normalizedOwasp)
    const affectedUrls = engine === "IAST"
        ? (Array.isArray(iastEvidence?.affectedUrls) ? iastEvidence.affectedUrls.slice() : [])
        : (Array.isArray(base.affectedUrls) ? base.affectedUrls.slice() : [])
    const sinkSummary = engine === "IAST"
        ? (iastEvidence?.sinkSummary && typeof iastEvidence.sinkSummary === "object" ? iastEvidence.sinkSummary : null)
        : (base.sinkSummary || null)
    const taintSummary = engine === "IAST"
        ? (iastEvidence?.taintSummary && typeof iastEvidence.taintSummary === "object" ? iastEvidence.taintSummary : null)
        : (base.taintSummary || null)
    const sinkId = engine === "IAST"
        ? (iastEvidence?.sinkId || null)
        : (base.sinkId || null)
    const taintSource = engine === "IAST"
        ? (iastEvidence?.taintSource || null)
        : (base.taintSource || null)
    const source = engine === "IAST"
        ? (iastEvidence?.source || null)
        : (base.source || null)
    const runtimeUrl = engine === "IAST"
        ? (iastEvidence?.routing?.runtimeUrl || iastEvidence?.routing?.url || null)
        : null
    return {
        ...base,
        engine: engine || null,
        severity: (base.severity || "").toLowerCase() || "medium",
        outputKind: base.outputKind || f.outputKind || null,
        reconKind: base.reconKind || f.reconKind || null,
        presentationAggregate: base.presentationAggregate || f.presentationAggregate || null,
        uiSurface: base.uiSurface || f.uiSurface || null,
        findingKind: base.findingKind || f.findingKind || null,
        owasp: normalizedOwasp,
        owaspPrimary,
        owaspLegacy,
        cwe: normalizedCwe,
        location: {
            url: runtimeUrl || loc.url || null,
            file: loc.file || null,
            line: loc.line || null,
            column: loc.column || null,
            pageUrl: loc.pageUrl || null,
            domPath: loc.domPath || null,
            elementId: loc.elementId || null,
            method: loc.method || null,
            param: loc.param || null
        },
        affectedUrls,
        sinkSummary,
        taintSummary,
        sinkId,
        taintSource,
        source
    }
}

function normalizeReconObservationAsFinding(observation) {
    if (!observation || typeof observation !== "object") return null
    const location = observation.location && typeof observation.location === "object"
        ? observation.location
        : {}
    return normalizeFinding({
        ...observation,
        engine: observation.engine || "DAST",
        severity: observation.severity || "info",
        findingKind: "recon",
        title: observation.ruleName || observation.moduleName || observation.name || "Recon observation",
        name: observation.ruleName || observation.moduleName || observation.name || "Recon observation",
        vulnId: observation.vulnId || observation.category || "recon",
        location: {
            url: location.url || location.runtimeUrl || null,
            method: location.method || null,
            param: location.param || null
        }
    })
}

function buildDastFindingMergeKey(finding = {}) {
    if (!finding || typeof finding !== "object") return ""
    const evidence = finding?.evidence?.dast && typeof finding.evidence.dast === "object"
        ? finding.evidence.dast
        : {}
    const aggregateKey = typeof evidence?.aggregate?.key === "string" ? evidence.aggregate.key.trim() : ""
    if (aggregateKey) {
        return `aggregate|${aggregateKey}`
    }
    const location = finding.location && typeof finding.location === "object" ? finding.location : {}
    const parts = [
        String(finding.engine || ""),
        String(finding.outputKind || ""),
        String(evidence.attackId || ""),
        String(evidence.requestId || ""),
        String(finding.ruleId || ""),
        String(finding.moduleId || ""),
        String(location.url || ""),
        String(location.method || ""),
        String(location.param || "")
    ]
    return parts.join("|")
}

function getDastOccurrenceCount(finding = {}) {
    const value = finding?.evidence?.dast?.occurrenceCount
    const count = Number(value)
    return Number.isFinite(count) && count > 0 ? count : 1
}

function getDastSampleLimit(finding = {}) {
    const value = finding?.evidence?.dast?.sampleLimit
    const limit = Number(value)
    return Number.isFinite(limit) && limit > 0 ? Math.max(1, Math.floor(limit)) : 10
}

function buildDastSampleKey(sample = {}) {
    const method = String(sample?.method || "").toUpperCase()
    const url = String(sample?.url || "")
    const runtimeUrl = String(sample?.runtimeUrl || "")
    if (sample?.requestId) {
        return [method, url, runtimeUrl, "request", String(sample.requestId)].join("|")
    }
    if (sample?.attackId) {
        return [method, url, runtimeUrl, "attack", String(sample.attackId)].join("|")
    }
    return [
        method,
        url,
        runtimeUrl,
        String(sample?.param || ""),
        String(sample?.proof || "")
    ].join("|")
}

function mergeDastAggregateFinding(target, incoming) {
    const targetEvidence = target?.evidence?.dast
    const incomingEvidence = incoming?.evidence?.dast
    if (!targetEvidence || typeof targetEvidence !== "object" || !incomingEvidence || typeof incomingEvidence !== "object") {
        return target
    }

    const sampleLimit = Math.max(getDastSampleLimit(target), getDastSampleLimit(incoming))
    targetEvidence.occurrenceCount = getDastOccurrenceCount(target) + getDastOccurrenceCount(incoming)
    targetEvidence.sampleLimit = sampleLimit
    targetEvidence.truncated = targetEvidence.truncated === true || incomingEvidence.truncated === true

    const samples = Array.isArray(targetEvidence.samples) ? targetEvidence.samples : []
    const seen = new Set(samples.map(buildDastSampleKey))
    const incomingSamples = Array.isArray(incomingEvidence.samples) ? incomingEvidence.samples : []
    incomingSamples.forEach((sample) => {
        if (!sample || typeof sample !== "object") return
        const key = buildDastSampleKey(sample)
        if (seen.has(key)) return
        seen.add(key)
        if (samples.length < sampleLimit) {
            samples.push(sample)
        } else {
            targetEvidence.truncated = true
        }
    })
    targetEvidence.samples = samples

    const targetConfidence = Number(target.confidence)
    const incomingConfidence = Number(incoming?.confidence)
    if (Number.isFinite(incomingConfidence) && (!Number.isFinite(targetConfidence) || incomingConfidence > targetConfidence)) {
        target.confidence = incomingConfidence
    }
    return target
}

function mergeDastFindings(primaryFindings = [], extraFindings = []) {
    const merged = []
    const seen = new Map()
    ;[...(Array.isArray(primaryFindings) ? primaryFindings : []), ...(Array.isArray(extraFindings) ? extraFindings : [])]
        .forEach((finding) => {
            if (!finding || typeof finding !== "object") return
            const key = buildDastFindingMergeKey(finding) || String(finding.id || "")
            if (key && seen.has(key)) {
                if (key.startsWith("aggregate|")) {
                    mergeDastAggregateFinding(seen.get(key), finding)
                }
                return
            }
            if (key) seen.set(key, finding)
            merged.push(finding)
        })
    return merged
}

function normalizeGroup(g) {
    if (!g || typeof g !== "object") return g
    return {
        ...g,
        engine: g.engine || null,
        severity: (g.severity || "").toLowerCase() || "medium",
        occurrenceIds: Array.isArray(g.occurrenceIds) ? g.occurrenceIds : []
    }
}

function normalizeAttackRecord(attack, attackIdx) {
    if (!attack || typeof attack !== "object") return null
    const attackId = attack.id || `atk-${attackIdx + 1}`
    return {
        ...attack,
        id: attackId
    }
}

function normalizeRequestRecord(record, index) {
    if (!record || typeof record !== "object") return null
    const attacks = Array.isArray(record.attacks)
        ? record.attacks.map((attack, idx) => normalizeAttackRecord(attack, idx)).filter(Boolean)
        : []
    return {
        id: record.id || `req-${index + 1}`,
        original: record.original || null,
        attacks
    }
}

function getRequestRecordSortMeta(record = {}) {
    const request = record?.original?.request && typeof record.original.request === "object"
        ? record.original.request
        : {}
    const discoverySource = String(request.discoverySource || "").trim().toLowerCase()
    const discoveryRank = discoverySource === "html_link" ? 1 : 0
    const id = String(record.id || "")
    const seqMatch = /^req-(\d+)$/i.exec(id)
    const requestSeq = seqMatch ? Number(seqMatch[1]) : null
    const timestamp = Number(request.timestamp ?? request.timeStamp ?? 0)
    const url = String(request.ui_url || request.url || "").toLowerCase()
    return {
        discoveryRank,
        requestSeq: Number.isFinite(requestSeq) ? requestSeq : null,
        timestamp: Number.isFinite(timestamp) ? timestamp : 0,
        url,
        id
    }
}

function compareRequestRecordsForDisplay(left, right) {
    const leftMeta = getRequestRecordSortMeta(left)
    const rightMeta = getRequestRecordSortMeta(right)
    if (leftMeta.discoveryRank !== rightMeta.discoveryRank) {
        return leftMeta.discoveryRank - rightMeta.discoveryRank
    }
    if (leftMeta.requestSeq !== null || rightMeta.requestSeq !== null) {
        if (leftMeta.requestSeq === null) return 1
        if (rightMeta.requestSeq === null) return -1
        if (leftMeta.requestSeq !== rightMeta.requestSeq) {
            return leftMeta.requestSeq - rightMeta.requestSeq
        }
    }
    if (leftMeta.timestamp !== rightMeta.timestamp) {
        return leftMeta.timestamp - rightMeta.timestamp
    }
    const urlDiff = leftMeta.url.localeCompare(rightMeta.url)
    if (urlDiff !== 0) return urlDiff
    return leftMeta.id.localeCompare(rightMeta.id)
}

function normalizeRequests(rawRequests = []) {
    return rawRequests
        .map((record, index) => normalizeRequestRecord(record, index))
        .filter(Boolean)
        .sort(compareRequestRecordsForDisplay)
}

function buildDastRouteLabel(record = {}) {
    const request = record?.original?.request && typeof record.original.request === "object"
        ? record.original.request
        : {}
    const method = String(request.method || "GET").toUpperCase()
    const rawUrl = String(request.url || request.ui_url || "").trim()
    if (!rawUrl) return `${method} <unknown>`
    try {
        const parsed = new URL(rawUrl)
        return `${method} ${parsed.pathname || "/"}`
    } catch (_) {
        return `${method} ${rawUrl}`
    }
}

function deriveDastScanHealth(raw = {}, normalizedRequests = []) {
    if (!Array.isArray(normalizedRequests) || !normalizedRequests.length) return null
    let totalAttacks = 0
    let failedAttacks = 0
    let requestsWithFailures = 0
    const routeFailures = new Map()

    normalizedRequests.forEach((record) => {
        const attacks = Array.isArray(record?.attacks) ? record.attacks : []
        let requestFailed = 0
        const routeLabel = buildDastRouteLabel(record)
        attacks.forEach((attack) => {
            totalAttacks += 1
            const statusLine = String(attack?.response?.statusLine || "")
            if (!/Failed to fetch/i.test(statusLine)) return
            failedAttacks += 1
            requestFailed += 1
        })
        if (requestFailed > 0) {
            requestsWithFailures += 1
            routeFailures.set(routeLabel, (routeFailures.get(routeLabel) || 0) + requestFailed)
        }
    })

    if (totalAttacks <= 0 || failedAttacks <= 0) return null

    const failedRate = failedAttacks / totalAttacks
    if (failedAttacks < 5 || failedRate < 0.08) return null

    const currentMaxRequestsPerSecond = Number(raw?.settings?.maxRequestsPerSecond || 0)
    const currentConcurrency = Number(raw?.settings?.concurrency || 0)
    let recommendedMaxRequestsPerSecond = null
    if (Number.isFinite(currentMaxRequestsPerSecond) && currentMaxRequestsPerSecond > 0) {
        if (currentMaxRequestsPerSecond > 3) recommendedMaxRequestsPerSecond = 3
        else if (currentMaxRequestsPerSecond > 2) recommendedMaxRequestsPerSecond = 2
        else if (failedRate >= 0.35 && currentMaxRequestsPerSecond > 1) recommendedMaxRequestsPerSecond = currentMaxRequestsPerSecond - 1
    }
    let recommendedConcurrency = null
    if (Number.isFinite(currentConcurrency) && currentConcurrency > 1) {
        recommendedConcurrency = 1
    }

    return {
        level: failedRate >= 0.35 || failedAttacks >= 20 ? "high" : "medium",
        totalAttacks,
        failedAttacks,
        failedRate,
        requestCount: normalizedRequests.length,
        requestsWithFailures,
        current: {
            maxRequestsPerSecond: Number.isFinite(currentMaxRequestsPerSecond) && currentMaxRequestsPerSecond > 0
                ? currentMaxRequestsPerSecond
                : null,
            concurrency: Number.isFinite(currentConcurrency) && currentConcurrency > 0
                ? currentConcurrency
                : null
        },
        recommended: {
            maxRequestsPerSecond: recommendedMaxRequestsPerSecond,
            concurrency: recommendedConcurrency
        },
        topRoutes: Array.from(routeFailures.entries())
            .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
            .slice(0, 3)
            .map(([route, failed]) => ({ route, failed }))
    }
}

function normalizeIastRequests(rawRequests = []) {
    return rawRequests
        .map((record, index) => {
            if (!record || typeof record !== "object") return null
            const method = String(record.method || "GET").toUpperCase()
            const url = record.url || null
            const displayUrl = record.displayUrl || url || null
            const key = record.key || `${method} ${displayUrl || ""}`.trim()
            return {
                id: record.id || `iast-req-${index + 1}`,
                key,
                method,
                url,
                displayUrl,
                status: record.status ?? null,
                host: record.host || null,
                type: record.type || "http",
                mimeType: record.mimeType || null,
                lastSeen: record.lastSeen ?? null
            }
        })
        .filter(Boolean)
}

function isReportableDastAttack(attack) {
    if (!attack || typeof attack !== "object") return false
    const rule = attack?.validation?.rule
    if (rule === false) return false
    const metaRule = attack?.metadata?.validation?.rule
    if (metaRule === false) return false
    return true
}

function buildFindingsFromNormalizedDastRequests(requests = [], result = {}) {
    const findings = []
    let fallbackSeq = 0

    requests.forEach((record, requestIdx) => {
        if (!record || typeof record !== "object") return
        const requestId = record.id || `req-${requestIdx + 1}`
        const originalRequest = record.original?.request || {}
        const attacks = Array.isArray(record.attacks) ? record.attacks : []

        attacks.forEach((attack, attackIdx) => {
            if (!attack?.success) return
            if (!isReportableDastAttack(attack)) return
            fallbackSeq += 1
            const meta = attack.metadata || {}
            const attackId = attack.id || `atk-${fallbackSeq}`
            const req = attack.request || originalRequest || {}
            const attacked = meta.attacked
            const paramName = attack.param ||
                meta.param ||
                (typeof attacked === "string" ? attacked : attacked?.name) ||
                null
            const fid = `ui-dast-${result.scanId || "scan"}-${requestId}-${attackId}`

            findings.push(normalizeFinding({
                id: fid,
                engine: "DAST",
                scanId: result.scanId || null,
                moduleId: attack.moduleId || meta.moduleId || null,
                moduleName: attack.moduleName || meta.moduleName || meta.module || null,
                ruleId: attack.ruleId || meta.id || meta.attackId || attackId,
                ruleName: attack.ruleName || attack.name || meta.name || meta.id || null,
                vulnId: attack.vulnId || meta.vulnId || meta.category || null,
                category: attack.category || meta.category || null,
                severity: attack.severity || meta.severity || "medium",
                outputKind: attack.outputKind || meta.outputKind || null,
                reconKind: attack.reconKind || meta.reconKind || null,
                presentationAggregate: attack.presentationAggregate || meta.presentationAggregate || null,
                uiSurface: attack.uiSurface || meta.uiSurface || null,
                findingKind: String(attack.outputKind || meta.outputKind || "").toLowerCase() === "recon" ? "recon" : null,
                owasp: meta.owasp || null,
                cwe: meta.cwe || null,
                tags: meta.tags || [],
                confidence: attack.confidence ?? meta.confidence ?? null,
                description: attack.description || meta.description || meta.docs?.description || "",
                recommendation: attack.recommendation || meta.recommendation || meta.docs?.recommendation || "",
                links: attack.links || meta.links || meta.docs?.links || {},
                location: {
                    url: req.url || req.href || null,
                    method: req.method || originalRequest?.method || null,
                    param: paramName
                },
                evidence: {
                    dast: {
                        attackId,
                        requestId,
                        param: attack.param || meta.param || null,
                        payload: attack.payload || meta.payload || null,
                        proof: attack.proof || null
                    }
                }
            }))
        })
    })

    return findings
}

function normalizeCoverage(coverage) {
    if (!coverage || typeof coverage !== "object") return null
    return {
        enginesPresent: Array.isArray(coverage.enginesPresent) ? coverage.enginesPresent : [],
        enginesMissing: Array.isArray(coverage.enginesMissing) ? coverage.enginesMissing : [],
        gaps: Array.isArray(coverage.gaps) ? coverage.gaps : [],
        limitations: Array.isArray(coverage.limitations) ? coverage.limitations : [],
        confidence: coverage.confidence || "low",
        confidenceScore: Number.isFinite(coverage.confidenceScore) ? Number(coverage.confidenceScore) : 0
    }
}

function normalizePattern(pattern) {
    if (!pattern || typeof pattern !== "object") return null
    return {
        id: pattern.id || null,
        title: pattern.title || "Pattern",
        ruleCode: pattern.ruleCode || null,
        type: pattern.type || null,
        routeKey: pattern.routeKey || null,
        paramKey: pattern.paramKey || null,
        signals: pattern.signals && typeof pattern.signals === "object" ? pattern.signals : {},
        evidenceRefs: Array.isArray(pattern.evidenceRefs) ? pattern.evidenceRefs : []
    }
}

function normalizeCandidate(candidate) {
    if (!candidate || typeof candidate !== "object") return null
    return {
        id: candidate.id || null,
        suppressKey: candidate.suppressKey || null,
        type: candidate.type || null,
        title: candidate.title || "Candidate",
        score: Number.isFinite(candidate.score) ? Number(candidate.score) : 0,
        confidence: candidate.confidence || "low",
        confidenceRank: Number.isFinite(candidate.confidenceRank) ? Number(candidate.confidenceRank) : 1,
        routeKey: candidate.routeKey || null,
        paramKey: candidate.paramKey || null,
        engineSignals: Array.isArray(candidate.engineSignals) ? candidate.engineSignals : [],
        why: Array.isArray(candidate.why) ? candidate.why : [],
        evidenceRefs: Array.isArray(candidate.evidenceRefs) ? candidate.evidenceRefs : [],
        manualSteps: Array.isArray(candidate.manualSteps) ? candidate.manualSteps : [],
        createdByRule: candidate.createdByRule || null,
        diffStatus: candidate.diffStatus || null
    }
}

function normalizeCodeArtifacts(codeArtifacts) {
    if (!codeArtifacts || typeof codeArtifacts !== "object") return null
    const sast = codeArtifacts.sast && typeof codeArtifacts.sast === "object"
        ? codeArtifacts.sast
        : null
    return {
        ...(sast ? {
            sast: {
                version: Number(sast.version || 2) || 2,
                routes: Array.isArray(sast.routes) ? sast.routes : [],
                endpoints: Array.isArray(sast.endpoints) ? sast.endpoints : [],
                graphql: Array.isArray(sast.graphql) ? sast.graphql : [],
                surfaces: Array.isArray(sast.surfaces) ? sast.surfaces : [],
                hiddenParams: Array.isArray(sast.hiddenParams) ? sast.hiddenParams : [],
                gadgets: Array.isArray(sast.gadgets) ? sast.gadgets : []
            }
        } : {})
    }
}

function normalizeIastDiscoveryBucket(bucket) {
    if (!bucket || typeof bucket !== "object") return null
    return {
        id: bucket.id || null,
        bucket: bucket.bucket || null,
        subtype: bucket.subtype || null,
        subtypes: Array.isArray(bucket.subtypes) ? bucket.subtypes : [],
        legacyFamilies: Array.isArray(bucket.legacyFamilies) ? bucket.legacyFamilies : [],
        routeKey: bucket.routeKey || null,
        paramKey: bucket.paramKey || null,
        priority: Number.isFinite(bucket.priority) ? Number(bucket.priority) : 0,
        severity: (bucket.severity || "").toLowerCase() || "info",
        hits: Number.isFinite(bucket.hits) ? Number(bucket.hits) : 0,
        sinkId: bucket.sinkId || null,
        sourceKinds: Array.isArray(bucket.sourceKinds) ? bucket.sourceKinds : [],
        dataKinds: Array.isArray(bucket.dataKinds) ? bucket.dataKinds : [],
        trustLevels: Array.isArray(bucket.trustLevels) ? bucket.trustLevels : [],
        trustDecisions: Array.isArray(bucket.trustDecisions) ? bucket.trustDecisions : [],
        crossOrigin: bucket.crossOrigin === true,
        routeControlled: bucket.routeControlled === true,
        sanitizedCount: Number.isFinite(bucket.sanitizedCount) ? Number(bucket.sanitizedCount) : 0,
        sanitizerIds: Array.isArray(bucket.sanitizerIds) ? bucket.sanitizerIds : [],
        thirdParty: bucket.thirdParty === true,
        authLike: bucket.authLike === true,
        corroboratingEngines: Array.isArray(bucket.corroboratingEngines) ? bucket.corroboratingEngines : [],
        candidateType: bucket.candidateType || null,
        evidenceRefs: Array.isArray(bucket.evidenceRefs) ? bucket.evidenceRefs : []
    }
}

function normalizeDiscovery(discovery) {
    if (!discovery || typeof discovery !== "object") return null
    return {
        iastBuckets: Array.isArray(discovery.iastBuckets)
            ? discovery.iastBuckets.map(normalizeIastDiscoveryBucket).filter(Boolean)
            : []
    }
}

function normalizeAttackMapItem(item) {
    if (!item || typeof item !== "object") return null
    return {
        id: item.id || null,
        source: item.source || null,
        title: item.title || "Attack map item",
        itemType: item.itemType || null,
        routeKey: item.routeKey || null,
        path: item.path || null,
        paramKey: item.paramKey || null,
        priority: Number.isFinite(item.priority) ? Number(item.priority) : 0,
        suggestedChecks: Array.isArray(item.suggestedChecks) ? item.suggestedChecks : [],
        evidenceRefs: Array.isArray(item.evidenceRefs) ? item.evidenceRefs : []
    }
}

function normalizeAttackMap(attackMap) {
    if (!attackMap || typeof attackMap !== "object") return null
    return {
        total: Number.isFinite(attackMap.total) ? Number(attackMap.total) : 0,
        items: Array.isArray(attackMap.items)
            ? attackMap.items.map(normalizeAttackMapItem).filter(Boolean)
            : []
    }
}

function normalizeInventoryIdentifier(entry) {
    if (!entry || typeof entry !== "object") return null
    return {
        id: entry.id || null,
        name: entry.name || null,
        kind: entry.kind || null,
        hits: Number.isFinite(entry.hits) ? Number(entry.hits) : 0,
        routeKeys: Array.isArray(entry.routeKeys) ? entry.routeKeys : [],
        sources: Array.isArray(entry.sources) ? entry.sources : [],
        evidenceRefs: Array.isArray(entry.evidenceRefs) ? entry.evidenceRefs : []
    }
}

function normalizeObjectInventory(objectInventory) {
    if (!objectInventory || typeof objectInventory !== "object") return null
    return {
        total: Number.isFinite(objectInventory.total) ? Number(objectInventory.total) : 0,
        identifiers: Array.isArray(objectInventory.identifiers)
            ? objectInventory.identifiers.map(normalizeInventoryIdentifier).filter(Boolean)
            : []
    }
}

function normalizeOpportunity(entry) {
    if (!entry || typeof entry !== "object") return null
    return {
        id: entry.id || null,
        source: entry.source || null,
        title: entry.title || "Opportunity",
        type: entry.type || null,
        routeKey: entry.routeKey || null,
        path: entry.path || null,
        paramKey: entry.paramKey || null,
        priority: Number.isFinite(entry.priority) ? Number(entry.priority) : 0,
        confidence: entry.confidence || "low",
        confidenceRank: Number.isFinite(entry.confidenceRank) ? Number(entry.confidenceRank) : 1,
        suggestedChecks: Array.isArray(entry.suggestedChecks) ? entry.suggestedChecks : [],
        evidenceRefs: Array.isArray(entry.evidenceRefs) ? entry.evidenceRefs : []
    }
}

function normalizeExplorerSummary(summary = {}) {
    return {
        routeCount: Number.isFinite(summary.routeCount) ? Number(summary.routeCount) : 0,
        endpointCount: Number.isFinite(summary.endpointCount) ? Number(summary.endpointCount) : 0,
        graphqlCount: Number.isFinite(summary.graphqlCount) ? Number(summary.graphqlCount) : 0,
        hiddenParamCount: Number.isFinite(summary.hiddenParamCount) ? Number(summary.hiddenParamCount) : 0,
        surfaceCount: Number.isFinite(summary.surfaceCount) ? Number(summary.surfaceCount) : 0,
        enginesPresent: Array.isArray(summary.enginesPresent) ? summary.enginesPresent : []
    }
}

function normalizeExplorerRoute(entry) {
    if (!entry || typeof entry !== "object") return null
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        path: entry.path || null,
        routeType: entry.routeType || null,
        enginesPresent: Array.isArray(entry.enginesPresent) ? entry.enginesPresent : [],
        sources: Array.isArray(entry.sources) ? entry.sources : [],
        authHints: Array.isArray(entry.authHints) ? entry.authHints : [],
        protocolHints: Array.isArray(entry.protocolHints) ? entry.protocolHints : [],
        environmentHints: Array.isArray(entry.environmentHints) ? entry.environmentHints : [],
        frameworks: Array.isArray(entry.frameworks) ? entry.frameworks : [],
        sourceKinds: Array.isArray(entry.sourceKinds) ? entry.sourceKinds : [],
        hintNames: Array.isArray(entry.hintNames) ? entry.hintNames : [],
        pageUrls: Array.isArray(entry.pageUrls) ? entry.pageUrls : [],
        adminLike: entry.adminLike === true,
        evidenceRefs: Array.isArray(entry.evidenceRefs) ? entry.evidenceRefs : []
    }
}

function normalizeExplorerEndpoint(entry) {
    if (!entry || typeof entry !== "object") return null
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        method: entry.method || null,
        path: entry.path || null,
        url: entry.url || null,
        enginesPresent: Array.isArray(entry.enginesPresent) ? entry.enginesPresent : [],
        sources: Array.isArray(entry.sources) ? entry.sources : [],
        transports: Array.isArray(entry.transports) ? entry.transports : [],
        authHints: Array.isArray(entry.authHints) ? entry.authHints : [],
        contentTypes: Array.isArray(entry.contentTypes) ? entry.contentTypes : [],
        paramNames: Array.isArray(entry.paramNames) ? entry.paramNames : [],
        bodyKeys: Array.isArray(entry.bodyKeys) ? entry.bodyKeys : [],
        headerNames: Array.isArray(entry.headerNames) ? entry.headerNames : [],
        discoveryTags: Array.isArray(entry.discoveryTags) ? entry.discoveryTags : [],
        environmentHints: Array.isArray(entry.environmentHints) ? entry.environmentHints : [],
        pageUrls: Array.isArray(entry.pageUrls) ? entry.pageUrls : [],
        adminLike: entry.adminLike === true,
        evidenceRefs: Array.isArray(entry.evidenceRefs) ? entry.evidenceRefs : []
    }
}

function normalizeExplorerGraphql(entry) {
    if (!entry || typeof entry !== "object") return null
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        method: entry.method || null,
        path: entry.path || null,
        url: entry.url || null,
        enginesPresent: Array.isArray(entry.enginesPresent) ? entry.enginesPresent : [],
        transports: Array.isArray(entry.transports) ? entry.transports : [],
        authHints: Array.isArray(entry.authHints) ? entry.authHints : [],
        operationTypes: Array.isArray(entry.operationTypes) ? entry.operationTypes : [],
        operationNames: Array.isArray(entry.operationNames) ? entry.operationNames : [],
        rootFields: Array.isArray(entry.rootFields) ? entry.rootFields : [],
        variableNames: Array.isArray(entry.variableNames) ? entry.variableNames : [],
        pageUrls: Array.isArray(entry.pageUrls) ? entry.pageUrls : [],
        adminLike: entry.adminLike === true,
        evidenceRefs: Array.isArray(entry.evidenceRefs) ? entry.evidenceRefs : []
    }
}

function normalizeExplorerHiddenParam(entry) {
    if (!entry || typeof entry !== "object") return null
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        method: entry.method || null,
        path: entry.path || null,
        paramName: entry.paramName || null,
        container: entry.container || null,
        hintTypes: Array.isArray(entry.hintTypes) ? entry.hintTypes : [],
        actions: Array.isArray(entry.actions) ? entry.actions : [],
        enginesPresent: Array.isArray(entry.enginesPresent) ? entry.enginesPresent : [],
        pageUrls: Array.isArray(entry.pageUrls) ? entry.pageUrls : [],
        adminLike: entry.adminLike === true,
        evidenceRefs: Array.isArray(entry.evidenceRefs) ? entry.evidenceRefs : []
    }
}

function normalizeExplorerSurface(entry) {
    if (!entry || typeof entry !== "object") return null
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        path: entry.path || null,
        surfaceType: entry.surfaceType || null,
        label: entry.label || null,
        hintNames: Array.isArray(entry.hintNames) ? entry.hintNames : [],
        enginesPresent: Array.isArray(entry.enginesPresent) ? entry.enginesPresent : [],
        pageUrls: Array.isArray(entry.pageUrls) ? entry.pageUrls : [],
        adminLike: entry.adminLike === true,
        evidenceRefs: Array.isArray(entry.evidenceRefs) ? entry.evidenceRefs : []
    }
}

function normalizeExplorer(explorer) {
    if (!explorer || typeof explorer !== "object") return null
    return {
        summary: normalizeExplorerSummary(explorer.summary || {}),
        routes: Array.isArray(explorer.routes)
            ? explorer.routes.map(normalizeExplorerRoute).filter(Boolean)
            : [],
        endpoints: Array.isArray(explorer.endpoints)
            ? explorer.endpoints.map(normalizeExplorerEndpoint).filter(Boolean)
            : [],
        graphql: Array.isArray(explorer.graphql)
            ? explorer.graphql.map(normalizeExplorerGraphql).filter(Boolean)
            : [],
        hiddenParams: Array.isArray(explorer.hiddenParams)
            ? explorer.hiddenParams.map(normalizeExplorerHiddenParam).filter(Boolean)
            : [],
        surfaces: Array.isArray(explorer.surfaces)
            ? explorer.surfaces.map(normalizeExplorerSurface).filter(Boolean)
            : []
    }
}

function normalizeAnalysis(analysis, topLevelVersion = null) {
    if (!analysis || typeof analysis !== "object") return null
    const meta = analysis.meta && typeof analysis.meta === "object"
        ? {
            computedAt: analysis.meta.computedAt || null,
            enginesPresent: Array.isArray(analysis.meta.enginesPresent) ? analysis.meta.enginesPresent : [],
            relatedScanCount: Number.isFinite(analysis.meta.relatedScanCount) ? Number(analysis.meta.relatedScanCount) : 0,
            relatedScanIds: Array.isArray(analysis.meta.relatedScanIds) ? analysis.meta.relatedScanIds : [],
            mode: analysis.meta.mode || null,
            forced: analysis.meta.forced === true
        }
        : null
    const diff = analysis.diff && typeof analysis.diff === "object"
        ? {
            baseScanId: analysis.diff.baseScanId || null,
            baseVersion: analysis.diff.baseVersion || null,
            baseCandidateCount: Number.isFinite(analysis.diff.baseCandidateCount) ? Number(analysis.diff.baseCandidateCount) : 0,
            addedCount: Number.isFinite(analysis.diff.addedCount) ? Number(analysis.diff.addedCount) : 0,
            changedCount: Number.isFinite(analysis.diff.changedCount) ? Number(analysis.diff.changedCount) : 0,
            unchangedCount: Number.isFinite(analysis.diff.unchangedCount) ? Number(analysis.diff.unchangedCount) : 0,
            removedCount: Number.isFinite(analysis.diff.removedCount) ? Number(analysis.diff.removedCount) : 0
        }
        : null
    return {
        version: analysis.version || topLevelVersion || null,
        scanId: analysis.scanId || null,
        coverage: normalizeCoverage(analysis.coverage) || {
            enginesPresent: [],
            enginesMissing: [],
            gaps: [],
            limitations: [],
            confidence: "low",
            confidenceScore: 0
        },
        patterns: Array.isArray(analysis.patterns)
            ? analysis.patterns.map(normalizePattern).filter(Boolean)
            : [],
        candidates: Array.isArray(analysis.candidates)
            ? analysis.candidates.map(normalizeCandidate).filter(Boolean)
            : [],
        discovery: normalizeDiscovery(analysis.discovery) || {
            iastBuckets: []
        },
        attackMap: normalizeAttackMap(analysis.attackMap) || {
            total: 0,
            items: []
        },
        objectInventory: normalizeObjectInventory(analysis.objectInventory) || {
            total: 0,
            identifiers: []
        },
        opportunities: Array.isArray(analysis.opportunities)
            ? analysis.opportunities.map(normalizeOpportunity).filter(Boolean)
            : [],
        explorer: normalizeExplorer(analysis.explorer) || {
            summary: normalizeExplorerSummary({}),
            routes: [],
            endpoints: [],
            graphql: [],
            hiddenParams: [],
            surfaces: []
        },
        meta,
        diff
    }
}

function normalizeLegacyDast(result) {
    const findings = []
    const items = Array.isArray(result.items) ? result.items : []
    const requests = []
    let attackSeq = 0
    items.forEach((item, requestIdx) => {
        if (!item) return
        const baseReq = item && item.original ? item.original : item?.request || {}
        const requestId = item.id ? `legacy-${item.id}` : `req-${requests.length + 1}`
        const requestRecord = {
            id: requestId,
            original: baseReq || null,
            attacks: []
        }
        const attacks = Array.isArray(item?.attacks) ? item.attacks : []
        attacks.forEach((attack, attackIdx) => {
            if (!attack) return
            attackSeq += 1
            const attackId = attack.id || `atk-${attackSeq}`
            const attackRecord = Object.assign({}, attack, { id: attackId })
            requestRecord.attacks.push(attackRecord)
            if (!attack.success) return
            if (!isReportableDastAttack(attackRecord)) return
            const meta = attack.metadata || {}
            const req = attack.request || baseReq || {}
            const fid = `legacy-dast-${result.scanId || "scan"}-${requestIdx}-${attackIdx}`
            const attacked = meta.attacked
            const paramName = meta.param ||
                (typeof attacked === "string" ? attacked : attacked?.name) ||
                null
            findings.push(normalizeFinding({
                id: fid,
                engine: "DAST",
                scanId: result.scanId || null,
                moduleId: meta.moduleId || null,
                moduleName: meta.moduleName || meta.module || null,
                ruleId: meta.id || meta.attackId || attackId,
                ruleName: meta.name || meta.id || null,
                vulnId: meta.vulnId || meta.category || null,
                category: meta.category || null,
                severity: meta.severity || "medium",
                outputKind: attackRecord.outputKind || meta.outputKind || null,
                reconKind: attackRecord.reconKind || meta.reconKind || null,
                presentationAggregate: attackRecord.presentationAggregate || meta.presentationAggregate || null,
                uiSurface: attackRecord.uiSurface || meta.uiSurface || null,
                findingKind: String(attackRecord.outputKind || meta.outputKind || "").toLowerCase() === "recon" ? "recon" : null,
                owasp: meta.owasp || null,
                cwe: meta.cwe || null,
                tags: meta.tags || [],
                description: attackRecord.description || meta.description || meta.docs?.description || "",
                recommendation: attackRecord.recommendation || meta.recommendation || meta.docs?.recommendation || "",
                links: attackRecord.links || meta.links || meta.docs?.links || {},
                location: {
                    url: req.url || req.href || null,
                    method: req.method || null,
                    param: paramName
                },
                evidence: {
                    dast: {
                        attackId: attackId,
                        requestId: requestId
                    }
                }
            }))
            attackRecord.findingId = fid
        })
        requests.push(requestRecord)
    })
    return {
        engine: "DAST",
        scanId: result.scanId || null,
        host: result.host || null,
        startedAt: result.startedAt || result.date || null,
        finishedAt: result.finishedAt || result.finished || null,
        stats: normalizeStats(result.stats || {}),
        findings,
        groups: [],
        requests,
        scanHealth: deriveDastScanHealth(result, requests),
        codeArtifacts: normalizeCodeArtifacts(result.codeArtifacts),
        analysis: normalizeAnalysis(result.analysis, result.analysisVersion),
        legacy: result
    }
}

function normalizeLegacySast(result) {
    const findings = []
    const items = Array.isArray(result.items) ? result.items : []
    items.forEach((item, idx) => {
        const ruleMeta = item.metadata || {}
        const moduleMeta = item.module_metadata || {}
        const fid = `legacy-sast-${result.scanId || "scan"}-${moduleMeta.id || "mod"}-${ruleMeta.id || idx}`
        findings.push(normalizeFinding({
            id: fid,
            engine: "SAST",
            scanId: result.scanId || null,
            moduleId: moduleMeta.id || null,
            moduleName: moduleMeta.name || null,
            ruleId: ruleMeta.rule_id || ruleMeta.id || null,
            ruleName: ruleMeta.name || ruleMeta.rule_id || ruleMeta.id || null,
            vulnId: moduleMeta.vulnId || moduleMeta.category || null,
            category: moduleMeta.category || null,
            severity: ruleMeta.severity || moduleMeta.severity || "medium",
            findingKind: item.findingKind || item?.evidence?.sast?.findingKind || ruleMeta.findingKind || "finding",
            owasp: moduleMeta.owasp || null,
            cwe: moduleMeta.cwe || null,
            tags: moduleMeta.tags || [],
            location: {
                file: item.codeFile || item.file || null,
                line: item.sink?.loc?.start?.line || item.source?.loc?.start?.line || null,
                column: item.sink?.loc?.start?.column || item.source?.loc?.start?.column || null,
                pageUrl: item.pageUrl || item.pageCanon || null
            },
            evidence: {
                sast: {
                    codeSnippet: item.codeSnippet || null,
                    source: item.source || null,
                    sink: item.sink || null
                }
            }
        }))
    })
    return {
        engine: "SAST",
        scanId: result.scanId || null,
        host: result.host || null,
        startedAt: result.startedAt || result.date || null,
        finishedAt: result.finishedAt || result.finished || null,
        stats: normalizeStats(result.stats || {}),
        findings,
        groups: [],
        codeArtifacts: normalizeCodeArtifacts(result.codeArtifacts),
        analysis: normalizeAnalysis(result.analysis, result.analysisVersion),
        legacy: result
    }
}

function normalizeLegacyIast(result) {
    const findings = []
    const items = Array.isArray(result.items) ? result.items : []
    items.forEach((item, itemIdx) => {
        const category = item.category || null
        const severity = item.severity || "medium"
        const affectedUrl = Array.isArray(item.affectedUrls) ? item.affectedUrls[0] : null
        const evs = Array.isArray(item.evidence) ? item.evidence : []
        evs.forEach((ev, evIdx) => {
            const raw = ev?.raw || {}
            const ctx = ev?.context || {}
            const fid = `legacy-iast-${result.scanId || "scan"}-${itemIdx}-${evIdx}`
            findings.push(normalizeFinding({
                id: fid,
                engine: "IAST",
                scanId: result.scanId || null,
                moduleId: ev?.moduleId || null,
                moduleName: ev?.moduleName || null,
                ruleId: raw.ruleId || null,
                ruleName: raw.ruleId || null,
                vulnId: category || null,
                category,
                severity,
                owasp: raw.owasp || null,
                cwe: raw.cwe || null,
                tags: raw.tags || [],
                location: {
                    url: affectedUrl || ctx.url || null,
                    domPath: ctx.domPath || null,
                    elementId: ctx.elementId || null
                },
                evidence: {
                    iast: {
                        flow: ctx.flow || [],
                        matched: ev.matched || null,
                        sinkId: raw.sinkId || null,
                        taintSource: raw.source || null,
                        domPath: ctx.domPath || null,
                        elementOuterHTML: ctx.elementOuterHTML || null,
                        value: ctx.value || null
                    }
                }
            }))
        })
    })
    return {
        engine: "IAST",
        scanId: result.scanId || null,
        host: result.host || null,
        startedAt: result.startedAt || result.date || null,
        finishedAt: result.finishedAt || result.finished || null,
        stats: normalizeStats(result.stats || {}),
        findings,
        groups: [],
        requests: normalizeIastRequests(result.requests || []),
        codeArtifacts: normalizeCodeArtifacts(result.codeArtifacts),
        analysis: normalizeAnalysis(result.analysis, result.analysisVersion),
        legacy: result
    }
}

export function normalizeScanResult(scanResult) {
    const raw = scanResult || {}
    const engine = raw.engine || inferEngineFromType(raw.type)
    const normalizedAnalysis = normalizeAnalysis(raw.analysis, raw.analysisVersion)
    const rawFindings = Array.isArray(raw.findings) ? raw.findings : []
    const rawRecon = Array.isArray(raw.recon) ? raw.recon : []
    const groups = Array.isArray(raw.groups) ? raw.groups : []
    const normalizedRequests = engine === "DAST"
        ? normalizeRequests(raw.requests || [])
        : (engine === "IAST" ? normalizeIastRequests(raw.requests || []) : [])
    const synthesizedFindings = engine === "DAST" && rawFindings.length === 0 && normalizedRequests.length > 0
        ? buildFindingsFromNormalizedDastRequests(normalizedRequests, raw)
        : rawFindings.map(normalizeFinding)
    const reconFindings = engine === "DAST"
        ? rawRecon.map(normalizeReconObservationAsFinding).filter(Boolean)
        : []
    const findings = engine === "DAST"
        ? mergeDastFindings(synthesizedFindings, reconFindings)
        : synthesizedFindings
    if (findings.length || groups.length || (engine === "DAST" && normalizedRequests.length)) {
        return {
            engine,
            scanId: raw.scanId || null,
            host: raw.host || null,
            startedAt: raw.startedAt || raw.date || null,
            finishedAt: raw.finishedAt || raw.finished || null,
            stats: normalizeStats(raw.stats || {}),
            findings,
            groups: groups.map(normalizeGroup),
            requests: normalizedRequests,
            scanHealth: engine === "DAST" ? deriveDastScanHealth(raw, normalizedRequests) : null,
            codeArtifacts: normalizeCodeArtifacts(raw.codeArtifacts),
            analysis: normalizedAnalysis,
            legacy: raw
        }
    }
    if (engine === "DAST") return normalizeLegacyDast(raw)
    if (engine === "SAST") return normalizeLegacySast(raw)
    if (engine === "IAST") return normalizeLegacyIast(raw)
    return {
        engine,
        scanId: raw.scanId || null,
        host: raw.host || null,
        startedAt: raw.startedAt || raw.date || null,
        finishedAt: raw.finishedAt || raw.finished || null,
        stats: normalizeStats(raw.stats || {}),
        findings: [],
        groups: [],
        requests: [],
        scanHealth: engine === "DAST" ? deriveDastScanHealth(raw, normalizedRequests) : null,
        codeArtifacts: normalizeCodeArtifacts(raw.codeArtifacts),
        analysis: normalizedAnalysis,
        legacy: raw
    }
}
