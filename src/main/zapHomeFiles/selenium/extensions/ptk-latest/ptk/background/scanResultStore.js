import CryptoES from "../packages/crypto-es/index.js"
import { createScanResultEnvelope } from "./common/scanResults.js"
import normalizeFinding from "./common/findingNormalizer.js"
import { applyScanAnalysis } from "./analysis/scanAnalysisEngine.js"
import { normalizeEngineName } from "./analysis/canonicalize.js"

function deepClone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function ensureNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const str = String(value).trim()
    return str.length ? str : null
}

function normalizeUrlForGrouping(rawUrl) {
    if (!rawUrl) return ""
    try {
        const parsed = new URL(rawUrl, rawUrl.startsWith("http") ? undefined : "http://placeholder")
        return `${parsed.protocol}//${parsed.host}${parsed.pathname}`
    } catch (_) {
        const safe = String(rawUrl)
        const idx = safe.search(/[?#]/)
        return idx >= 0 ? safe.slice(0, idx) : safe
    }
}

function normalizeHostKey(host) {
    if (host === undefined || host === null) return ""
    return String(host).trim().toLowerCase()
}

function toTimestamp(value) {
    if (!value) return 0
    const ts = Date.parse(String(value))
    return Number.isFinite(ts) ? ts : 0
}

function buildGroupId({ engine, scanId, vulnId, category, url, sinkId, ruleId, moduleId }) {
    const normalizedUrl = normalizeUrlForGrouping(url)
    const payload = [
        engine || "",
        scanId || "",
        vulnId || "",
        category || "",
        normalizedUrl || "",
        sinkId || "",
        ruleId || "",
        moduleId || ""
    ].join("|")
    const hash = CryptoES.SHA256(payload).toString(CryptoES.enc.Hex)
    return `${engine || "SCAN"}::${hash}`
}

function defaultStats() {
    return {
        findingsCount: 0,
        attacksCount: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    }
}

const ANALYSIS_LATE_RECOMPUTE_GRACE_MS = 2000
const ENGINE_ORDER = Object.freeze(["DAST", "IAST", "SAST", "SCA"])
const RELATED_ENGINE_WINDOW_MS = 24 * 60 * 60 * 1000

function sortEngines(engines = []) {
    const deduped = Array.from(new Set((Array.isArray(engines) ? engines : []).filter(Boolean)))
    return deduped.sort((a, b) => {
        const aIdx = ENGINE_ORDER.indexOf(a)
        const bIdx = ENGINE_ORDER.indexOf(b)
        if (aIdx >= 0 && bIdx >= 0) return aIdx - bIdx
        if (aIdx >= 0) return -1
        if (bIdx >= 0) return 1
        return String(a).localeCompare(String(b))
    })
}

class ScanResultStore {
    constructor() {
        this._scans = new Map()
        this._analysisFinalizeWindows = new Map()
    }

    createScan({ engine, scanId, host, startedAt, settings = {}, policyId = null, extraFields = {} } = {}) {
        if (!engine) throw new Error("engine is required to create scan")
        if (!scanId) throw new Error("scanId is required to create scan")
        const envelope = createScanResultEnvelope({
            engine,
            scanId,
            host,
            startedAt,
            settings
        })
        envelope.policyId = policyId || null
        envelope.tabId = extraFields.tabId || null
        envelope.stats = defaultStats()
        Object.keys(extraFields || {}).forEach(key => {
            if (key === "tabId") return
            envelope[key] = extraFields[key]
        })
        this._scans.set(scanId, envelope)
        return envelope
    }

    hydrateScan(envelope = {}, { engineFallback = null, extraFields = {} } = {}) {
        if (!envelope) return null
        const scanId = envelope.scanId || envelope.id || null
        const engine = envelope.engine || engineFallback
        if (!scanId || !engine) return null
        const scan = this.createScan({
            engine,
            scanId,
            host: envelope.host || null,
            startedAt: envelope.startedAt || envelope.date || new Date().toISOString(),
            settings: envelope.settings || {},
            policyId: envelope.policyId || null,
            extraFields: {
                ...extraFields,
                httpEvents: Array.isArray(envelope.httpEvents) ? envelope.httpEvents : (extraFields.httpEvents || []),
                runtimeEvents: Array.isArray(envelope.runtimeEvents) ? envelope.runtimeEvents : (extraFields.runtimeEvents || []),
                requests: Array.isArray(envelope.requests) ? envelope.requests : (extraFields.requests || []),
                pages: Array.isArray(envelope.pages) ? envelope.pages : (extraFields.pages || []),
                files: Array.isArray(envelope.files) ? envelope.files : (extraFields.files || [])
            }
        })
        scan.finishedAt = envelope.finishedAt || envelope.finished || null
        scan.stats = { ...defaultStats(), ...(envelope.stats || {}) }
        scan.groups = Array.isArray(envelope.groups) ? envelope.groups : []
        scan.items = Array.isArray(envelope.items) ? envelope.items : []
        if (envelope.analysis && typeof envelope.analysis === "object") {
            scan.analysis = deepClone(envelope.analysis)
        }
        if (envelope.analysisVersion) {
            scan.analysisVersion = envelope.analysisVersion
            if (scan.analysis && !scan.analysis.version) {
                scan.analysis.version = envelope.analysisVersion
            }
        }
        const findings = Array.isArray(envelope.findings) ? envelope.findings : []
        scan.findings = []
        findings.forEach(f => {
            this.upsertFinding({
                scanId,
                engine,
                finding: f,
                moduleMeta: {},
                ruleMeta: {}
            })
        })
        return scan
    }

    getScan(scanId) {
        if (!scanId) return null
        return this._scans.get(scanId) || null
    }

    deleteScan(scanId) {
        if (!scanId) return
        this._scans.delete(scanId)
        this._analysisFinalizeWindows.delete(scanId)
    }

    setFinished(scanId, finishedAt = new Date().toISOString()) {
        const scan = this.getScan(scanId)
        if (!scan) return
        scan.finishedAt = finishedAt || new Date().toISOString()
        this._applyAnalysisSafe(scan, { force: true })
        this._analysisFinalizeWindows.set(scanId, {
            graceUntilMs: Date.now() + ANALYSIS_LATE_RECOMPUTE_GRACE_MS,
            recomputed: false
        })
    }

    upsertFinding({ scanId, engine, finding, moduleMeta = {}, ruleMeta = {} } = {}) {
        if (!scanId || !engine || !finding) return null
        const scan = this.getScan(scanId)
        if (!scan) return null
        const normalized = normalizeFinding({
            engine,
            scanId,
            finding,
            moduleMeta: moduleMeta?.metadata || moduleMeta,
            ruleMeta: ruleMeta?.metadata || ruleMeta
        })
        if (!Array.isArray(scan.findings)) {
            scan.findings = []
        }

        // Initialize indexes for O(1) lookups if not present
        if (!scan._findingIdIndex) {
            scan._findingIdIndex = new Map()
            scan._findingFingerprintIndex = new Map()
            // Build indexes from existing findings
            scan.findings.forEach((f, idx) => {
                if (f?.id) scan._findingIdIndex.set(f.id, idx)
                if (f?.fingerprint) scan._findingFingerprintIndex.set(f.fingerprint, idx)
            })
        }

        // O(1) lookup instead of O(n) findIndex
        let existingIdx = -1
        if (normalized.id && scan._findingIdIndex.has(normalized.id)) {
            existingIdx = scan._findingIdIndex.get(normalized.id)
        } else if (normalized.fingerprint && scan._findingFingerprintIndex.has(normalized.fingerprint)) {
            existingIdx = scan._findingFingerprintIndex.get(normalized.fingerprint)
        }

        if (existingIdx >= 0) {
            // Update existing finding - adjust stats if severity changed
            const oldFinding = scan.findings[existingIdx]
            const oldSeverity = String(oldFinding?.severity || "info").toLowerCase()
            const newSeverity = String(normalized.severity || "info").toLowerCase()

            scan.findings[existingIdx] = { ...oldFinding, ...normalized, updatedAt: normalized.updatedAt }

            // Incremental stats update if severity changed
            if (oldSeverity !== newSeverity) {
                this._adjustStat(scan, oldSeverity, -1)
                this._adjustStat(scan, newSeverity, +1)
            }
        } else {
            // New finding - add to array and indexes
            const newIdx = scan.findings.length
            scan.findings.push(normalized)

            // Update indexes
            if (normalized.id) scan._findingIdIndex.set(normalized.id, newIdx)
            if (normalized.fingerprint) scan._findingFingerprintIndex.set(normalized.fingerprint, newIdx)

            // Incremental stats update
            this._adjustStat(scan, String(normalized.severity || "info").toLowerCase(), +1)
            scan.stats.findingsCount++

            // Incremental group update
            this._addFindingToGroup(scan, normalized)
        }

        this._maybeApplyLateAnalysisRecompute(scanId, scan)

        return normalized
    }

    _maybeApplyLateAnalysisRecompute(scanId, scan) {
        if (!scanId || !scan || typeof scan !== "object") return
        const windowState = this._analysisFinalizeWindows.get(scanId)
        if (!windowState || typeof windowState !== "object") return
        if (windowState.recomputed) return
        if (Date.now() > Number(windowState.graceUntilMs || 0)) {
            this._analysisFinalizeWindows.delete(scanId)
            return
        }
        this._applyAnalysisSafe(scan, { force: true })
        windowState.recomputed = true
        this._analysisFinalizeWindows.set(scanId, windowState)
    }

    // Incremental stat adjustment - O(1) instead of O(n)
    _adjustStat(scan, severity, delta) {
        if (!scan.stats) scan.stats = defaultStats()
        const sev = String(severity || "info").toLowerCase()
        if (Object.prototype.hasOwnProperty.call(scan.stats, sev)) {
            scan.stats[sev] = Math.max(0, (scan.stats[sev] || 0) + delta)
        } else {
            scan.stats.info = Math.max(0, (scan.stats.info || 0) + delta)
        }
    }

    // Incremental group addition - O(1) instead of O(n)
    _addFindingToGroup(scan, finding) {
        if (!finding) return

        // Initialize group map for O(1) lookups if not present
        if (!scan._groupMap) {
            scan._groupMap = new Map()
            // Build map from existing groups
            if (Array.isArray(scan.groups)) {
                scan.groups.forEach(g => {
                    if (g?.id) scan._groupMap.set(g.id, g)
                })
            }
        }

        const sinkId = finding?.evidence?.iast?.sinkId
            || finding?.evidence?.dast?.attackId
            || finding?.evidence?.sast?.sinkId
            || finding.sinkId
            || null
        const runtimeUrl = finding?.location?.runtimeUrl
            || finding?.evidence?.iast?.routing?.runtimeUrl
            || finding?.evidence?.iast?.routing?.url
            || finding?.location?.url
            || null
        const groupId = buildGroupId({
            engine: finding.engine,
            scanId: finding.scanId,
            vulnId: finding.vulnId,
            category: finding.category,
            url: runtimeUrl,
            sinkId,
            ruleId: finding.ruleId,
            moduleId: finding.moduleId
        })

        let group = scan._groupMap.get(groupId)
        if (!group) {
            group = {
                id: groupId,
                engine: finding.engine,
                scanId: finding.scanId,
                vulnId: finding.vulnId,
                category: finding.category,
                severity: finding.severity,
                correlationKey: finding.correlationKey || null,
                location: {
                    url: (finding.engine === 'IAST' ? runtimeUrl : normalizeUrlForGrouping(runtimeUrl)) || null,
                    runtimeUrl: runtimeUrl || null,
                    file: finding?.location?.file || null,
                    param: finding?.location?.param || null,
                    sink: sinkId || null
                },
                occurrenceIds: [],
                count: 0
            }
            scan._groupMap.set(groupId, group)
            if (!Array.isArray(scan.groups)) scan.groups = []
            scan.groups.push(group)
        }

        const occurrenceId = finding.id || `${group.id}::${group.occurrenceIds.length + 1}`
        group.occurrenceIds.push(occurrenceId)
        group.count = group.occurrenceIds.length
    }

    // Full recalculation - only used during hydration or when needed
    _recalculateStats(scan) {
        const stats = defaultStats()
        const findings = Array.isArray(scan.findings) ? scan.findings : []
        findings.forEach(finding => {
            if (!finding) return
            stats.findingsCount += 1
            const severity = String(finding.severity || "info").toLowerCase()
            if (Object.prototype.hasOwnProperty.call(stats, severity)) {
                stats[severity] = (stats[severity] || 0) + 1
            } else {
                stats.info = (stats.info || 0) + 1
            }
        })
        scan.stats = stats
    }

    // Full rebuild - only used during hydration or when needed
    _rebuildGroups(scan) {
        const groups = new Map()
        const findings = Array.isArray(scan.findings) ? scan.findings : []
        findings.forEach(finding => {
            if (!finding) return
            const sinkId = finding?.evidence?.iast?.sinkId
                || finding?.evidence?.dast?.attackId
                || finding?.evidence?.sast?.sinkId
                || finding.sinkId
                || null
            const runtimeUrl = finding?.location?.runtimeUrl
                || finding?.evidence?.iast?.routing?.runtimeUrl
                || finding?.evidence?.iast?.routing?.url
                || finding?.location?.url
                || null
            const groupId = buildGroupId({
                engine: finding.engine,
                scanId: finding.scanId,
                vulnId: finding.vulnId,
                category: finding.category,
                url: runtimeUrl,
                sinkId,
                ruleId: finding.ruleId,
                moduleId: finding.moduleId
            })
            if (!groups.has(groupId)) {
                groups.set(groupId, {
                    id: groupId,
                    engine: finding.engine,
                    scanId: finding.scanId,
                    vulnId: finding.vulnId,
                    category: finding.category,
                    severity: finding.severity,
                    correlationKey: finding.correlationKey || null,
                    location: {
                        url: (finding.engine === 'IAST' ? runtimeUrl : normalizeUrlForGrouping(runtimeUrl)) || null,
                        runtimeUrl: runtimeUrl || null,
                        file: finding?.location?.file || null,
                        param: finding?.location?.param || null,
                        sink: sinkId || null
                    },
                    occurrenceIds: [],
                    count: 0
                })
            }
            const group = groups.get(groupId)
            const occurrenceId = finding.id || `${group.id}::${group.occurrenceIds.length + 1}`
            group.occurrenceIds.push(occurrenceId)
            group.count = group.occurrenceIds.length
        })
        scan.groups = Array.from(groups.values())
        // Also update the group map for future incremental updates
        scan._groupMap = groups
    }

    exportScanResult(scanId) {
        const scan = this.getScan(scanId)
        if (!scan) return null
        this._applyAnalysisSafe(scan, { force: false })
        this._assertFindingIntegrity(scan)
        return deepClone(scan)
    }

    findLatestScanId({ engine = null, host = null, tabId = null } = {}) {
        const engineKey = normalizeEngineName(engine)
        const hostKey = normalizeHostKey(host)
        const hasTabHint = tabId !== undefined && tabId !== null
        let bestId = null
        let bestScore = -1

        this._scans.forEach((scan, scanId) => {
            if (!scan || typeof scan !== "object") return
            const scanEngine = normalizeEngineName(scan.engine)
            if (engineKey && scanEngine !== engineKey) return
            if (hostKey && normalizeHostKey(scan.host) !== hostKey) return
            if (hasTabHint && scan.tabId !== undefined && scan.tabId !== null && scan.tabId !== tabId) return

            const tabBoost = hasTabHint && scan.tabId === tabId ? 1 : 0
            const ts = toTimestamp(scan.finishedAt || scan.finished || scan.startedAt || null)
            const score = (tabBoost * 10_000_000_000_000) + ts
            if (score > bestScore) {
                bestScore = score
                bestId = String(scanId)
            }
        })

        return bestId
    }

    listScans() {
        return Array.from(this._scans.values()).map(entry => deepClone(entry))
    }

    getRelatedScansForAnalysis({
        scanId = null,
        host = null,
        tabId = null,
        engine = null,
        windowMs = RELATED_ENGINE_WINDOW_MS,
        includeSameEngine = false
    } = {}) {
        const currentScan = scanId ? this.getScan(scanId) : null
        const currentScanId = String(scanId || currentScan?.scanId || "")
        const hostKey = normalizeHostKey(host || currentScan?.host || "")
        const effectiveTabId = tabId !== undefined && tabId !== null ? tabId : (currentScan?.tabId ?? null)
        const currentEngine = normalizeEngineName(engine || currentScan?.engine || null)
        const centerTs = toTimestamp(currentScan?.finishedAt || currentScan?.finished || currentScan?.startedAt || null)
        const effectiveWindowMs = Number(windowMs || 0) > 0 ? Number(windowMs) : RELATED_ENGINE_WINDOW_MS
        const related = []

        this._scans.forEach((scan, candidateScanId) => {
            if (!scan || typeof scan !== "object") return
            if (currentScanId && String(candidateScanId) === currentScanId) return
            if (hostKey && normalizeHostKey(scan?.host) !== hostKey) return

            const candidateEngine = normalizeEngineName(scan?.engine)
            if (!candidateEngine) return
            if (!includeSameEngine && currentEngine && candidateEngine === currentEngine) return

            const finishedTs = toTimestamp(scan?.finishedAt || scan?.finished || null)
            if (finishedTs <= 0) return
            if (centerTs > 0 && Math.abs(centerTs - finishedTs) > effectiveWindowMs) return

            related.push(deepClone(scan))
        })

        return related.sort((a, b) => {
            const aSameTab = effectiveTabId !== null && effectiveTabId !== undefined && a?.tabId === effectiveTabId ? 1 : 0
            const bSameTab = effectiveTabId !== null && effectiveTabId !== undefined && b?.tabId === effectiveTabId ? 1 : 0
            if (bSameTab !== aSameTab) return bSameTab - aSameTab
            const aTs = toTimestamp(a?.finishedAt || a?.finished || a?.startedAt || null)
            const bTs = toTimestamp(b?.finishedAt || b?.finished || b?.startedAt || null)
            if (bTs !== aTs) return bTs - aTs
            return String(a?.scanId || "").localeCompare(String(b?.scanId || ""))
        })
    }

    _assertFindingIntegrity(scan) {
        const findings = Array.isArray(scan.findings) ? scan.findings : []
        findings.forEach(finding => {
            if (!finding) return
            const category = ensureNonEmptyString(finding.category)
            if (!category) {
                throw new Error(`[PTK ScanStore] Finding ${finding.id || "unknown"} missing category (metadata missing or not loaded)`)
            }
            const vulnId = ensureNonEmptyString(finding.vulnId)
            if (!vulnId) {
                throw new Error(`[PTK ScanStore] Finding ${finding.id || "unknown"} missing vulnId (metadata missing or not loaded)`)
            }
            if (finding.moduleId === "iast_dom_xss" && vulnId.toLowerCase() === "other") {
                throw new Error("[PTK ScanStore] IAST DOM XSS findings require a module vulnId (metadata missing or not loaded)")
            }
        })
    }

    _findPreviousAnalysisBase(scan) {
        if (!scan || typeof scan !== "object") return null
        const currentScanId = String(scan?.scanId || "")
        const currentHost = normalizeHostKey(scan?.host)
        const currentEngine = normalizeEngineName(scan?.engine)
        const currentFinishedTs = toTimestamp(scan?.finishedAt || scan?.finished || null)
        let best = null
        let bestTs = 0

        this._scans.forEach((candidate, scanId) => {
            if (!candidate || typeof candidate !== "object") return
            if (String(scanId) === currentScanId) return
            if (!candidate?.analysis || typeof candidate.analysis !== "object") return
            if (currentHost && normalizeHostKey(candidate?.host) !== currentHost) return
            const candidateEngine = normalizeEngineName(candidate?.engine)
            if (currentEngine && candidateEngine && candidateEngine !== currentEngine) return
            const candidateTs = toTimestamp(candidate?.finishedAt || candidate?.finished || null)
            if (candidateTs <= 0) return
            if (currentFinishedTs > 0 && candidateTs >= currentFinishedTs) return
            if (!best || candidateTs > bestTs || (candidateTs === bestTs && String(candidate?.scanId || "").localeCompare(String(best?.scanId || "")) < 0)) {
                best = candidate
                bestTs = candidateTs
            }
        })

        return best
    }

    _deriveExtraEnginesPresent(scan) {
        if (!scan || typeof scan !== "object") return []
        const engines = new Set()

        this.getRelatedScansForAnalysis({ scanId: scan?.scanId, host: scan?.host, tabId: scan?.tabId, engine: scan?.engine }).forEach((candidate) => {
            const candidateEngine = normalizeEngineName(candidate?.engine)
            if (!candidateEngine) return
            const hasSignals = (
                (Array.isArray(candidate?.findings) && candidate.findings.length > 0)
                || (Array.isArray(candidate?.requests) && candidate.requests.length > 0)
                || (Array.isArray(candidate?.runtimeEvents) && candidate.runtimeEvents.length > 0)
                || (Array.isArray(candidate?.files) && candidate.files.length > 0)
                || Number(candidate?.stats?.findingsCount || 0) > 0
                || Number(candidate?.stats?.attacksCount || 0) > 0
                || Number(candidate?.scanStats?.totalJobsExecuted || 0) > 0
            )
            if (hasSignals) {
                engines.add(candidateEngine)
            }
        })

        return sortEngines(Array.from(engines))
    }

    _applyAnalysisSafe(scan, opts = {}) {
        if (!scan || typeof scan !== "object") return
        try {
            const previous = this._findPreviousAnalysisBase(scan)
            const relatedScans = this.getRelatedScansForAnalysis({
                scanId: scan?.scanId,
                host: scan?.host,
                tabId: scan?.tabId,
                engine: scan?.engine
            })
            const extraEnginesPresent = this._deriveExtraEnginesPresent(scan)
            applyScanAnalysis(scan, {
                ...opts,
                extraEnginesPresent,
                previousAnalysis: previous?.analysis || null,
                relatedScans
            })
        } catch (err) {
            try { console.warn("[PTK ScanStore] scan analysis failed", err?.message || err) } catch (_) { }
        }
    }
}

export const scanResultStore = new ScanResultStore()

export { ScanResultStore }
export default scanResultStore
