import { ANALYSIS_VERSION, applyScanAnalysis } from "../../analysis/scanAnalysisEngine.js"
import { buildHostCoverageAnalysis } from "../../analysis/hostCoverageAnalysis.js"

const FROZEN_ANALYSIS_CONTEXT_PROP = "__ptkDastFrozenAnalysisContext"

function deepClone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

export class DastAnalysisService {
    constructor({
        storage = null,
        scanResultStore = null,
        diffBaseStorageKey = "ptk_dast_analysis_diff_base_v1",
        suppressionsStorageKey = "ptk_dast_analysis_suppressions_v1",
        getAppState = () => (typeof self !== "undefined" ? self?.ptk_app : null),
        getCurrentScanResult = () => null,
        getEngineIsRunning = () => false
    } = {}) {
        this.storage = storage
        this.scanResultStore = scanResultStore
        this.diffBaseStorageKey = diffBaseStorageKey
        this.suppressionsStorageKey = suppressionsStorageKey
        this.getAppState = getAppState
        this.getCurrentScanResult = getCurrentScanResult
        this.getEngineIsRunning = getEngineIsRunning
        this.diffBases = {}
        this.suppressions = {}
    }

    _unwrapStoredScan(value) {
        if (value && typeof value === "object" && value.scanResult && typeof value.scanResult === "object") {
            return value.scanResult
        }
        return value
    }

    async loadState() {
        const [diffBases, suppressions] = await Promise.all([
            this.storage?.getItem ? this.storage.getItem(this.diffBaseStorageKey) : Promise.resolve({}),
            this.storage?.getItem ? this.storage.getItem(this.suppressionsStorageKey) : Promise.resolve({})
        ])
        this.diffBases = diffBases && typeof diffBases === "object" ? diffBases : {}
        this.suppressions = suppressions && typeof suppressions === "object" ? suppressions : {}
        return {
            diffBases: this.diffBases,
            suppressions: this.suppressions
        }
    }

    normalizeHost(host) {
        if (host === null || host === undefined) return ""
        return String(host).trim().toLowerCase()
    }

    normalizeAnalysisHostKey(host) {
        return this.normalizeHost(host).replace(/^https?:\/\//, "").replace(/\/+$/, "")
    }

    isHostMatch(candidateHost, expectedHost) {
        const expected = this.normalizeHost(expectedHost)
        if (!expected) return true
        const candidate = this.normalizeHost(candidateHost)
        if (!candidate) return true
        return candidate === expected
    }

    isCompletedEngineScan(scanResult, { isRunning = false, expectedHost = null } = {}) {
        if (isRunning) return false
        if (!scanResult || typeof scanResult !== "object") return false
        if (!this.isHostMatch(scanResult.host, expectedHost)) return false
        return !!(scanResult.finishedAt || scanResult.finished)
    }

    hasCurrentAnalysis(scanResult) {
        if (!scanResult || typeof scanResult !== "object") return false
        if (!(scanResult?.finishedAt || scanResult?.finished)) return false
        return String(scanResult?.analysis?.version || scanResult?.analysisVersion || "").trim() === ANALYSIS_VERSION
    }

    ensureRelatedScanAnalysis(scan) {
        if (!scan || typeof scan !== "object") return scan
        if (this.scanResultStore?._applyAnalysisSafe) {
            this.scanResultStore._applyAnalysisSafe(scan, { force: false })
        }
        return scan
    }

    _getFrozenAnalysisContext(scanResult) {
        if (!scanResult || typeof scanResult !== "object") return null
        return scanResult[FROZEN_ANALYSIS_CONTEXT_PROP] && typeof scanResult[FROZEN_ANALYSIS_CONTEXT_PROP] === "object"
            ? scanResult[FROZEN_ANALYSIS_CONTEXT_PROP]
            : null
    }

    _getStoredAnalysisContext(scanResult) {
        if (!scanResult || typeof scanResult !== "object") return null
        const frozen = this._getFrozenAnalysisContext(scanResult)
        if (frozen && typeof frozen === "object") {
            return frozen
        }
        const meta = scanResult?.analysis?.meta
        if (meta && typeof meta === "object") {
            return meta
        }
        return null
    }

    _setFrozenAnalysisContext(scanResult, snapshot) {
        if (!scanResult || typeof scanResult !== "object" || !snapshot || typeof snapshot !== "object") return
        try {
            Object.defineProperty(scanResult, FROZEN_ANALYSIS_CONTEXT_PROP, {
                value: snapshot,
                writable: true,
                configurable: true,
                enumerable: false
            })
        } catch (_) {
            scanResult[FROZEN_ANALYSIS_CONTEXT_PROP] = snapshot
        }
    }

    _buildRelatedScansIdentitySignature(relatedScans = []) {
        const entries = (Array.isArray(relatedScans) ? relatedScans : [])
            .filter((scan) => scan && typeof scan === "object")
            .map((scan) => [
                String(scan?.scanId || ""),
                String(scan?.engine || "").toUpperCase(),
                String(scan?.host || ""),
                String(scan?.tabId ?? ""),
                String(scan?.finishedAt || scan?.finished || scan?.startedAt || ""),
                Number(Array.isArray(scan?.findings) ? scan.findings.length : 0),
                Number(Array.isArray(scan?.requests) ? scan.requests.length : 0),
                Number(Array.isArray(scan?.runtimeEvents) ? scan.runtimeEvents.length : 0),
                Number(Array.isArray(scan?.files) ? scan.files.length : 0)
            ].join("|"))
            .sort((a, b) => a.localeCompare(b))
        return entries.join("||")
    }

    _hasSignals(scan = {}) {
        return (
            (Array.isArray(scan?.findings) && scan.findings.length > 0)
            || (Array.isArray(scan?.requests) && scan.requests.length > 0)
            || (Array.isArray(scan?.runtimeEvents) && scan.runtimeEvents.length > 0)
            || (Array.isArray(scan?.files) && scan.files.length > 0)
            || Number(scan?.stats?.findingsCount || 0) > 0
            || Number(scan?.stats?.attacksCount || 0) > 0
            || Number(scan?.scanStats?.totalJobsExecuted || 0) > 0
        )
    }

    _deriveExtraEnginesPresentFromInputs({ scanResult = null, relatedScans = [], engineIsRunning = this.getEngineIsRunning() === true } = {}) {
        const engines = new Set(this.deriveCrossEnginePresence({ scanResult, engineIsRunning }))
        ;(Array.isArray(relatedScans) ? relatedScans : []).forEach((scan) => {
            if (!scan || typeof scan !== "object") return
            const engine = String(scan?.engine || "").toUpperCase()
            if (!engine) return
            if (this._hasSignals(scan)) {
                engines.add(engine)
            }
        })
        return Array.from(engines).sort((a, b) => a.localeCompare(b))
    }

    _buildLiveAnalysisInputs(scanResult = this.getCurrentScanResult?.() || null, { engineIsRunning = this.getEngineIsRunning() === true } = {}) {
        const relatedScans = this.getRelatedScansForCoverage(scanResult)
        const extraEnginesPresent = this._deriveExtraEnginesPresentFromInputs({
            scanResult,
            relatedScans,
            engineIsRunning
        })
        return {
            relatedScans,
            extraEnginesPresent,
            relatedScansSignature: this._buildRelatedScansIdentitySignature(relatedScans),
            extraEnginesSignature: extraEnginesPresent.join(",")
        }
    }

    _resolveStableAnalysisInputs(scanResult = this.getCurrentScanResult?.() || null, { force = false, engineIsRunning = this.getEngineIsRunning() === true } = {}) {
        const live = this._buildLiveAnalysisInputs(scanResult, { engineIsRunning })
        if (!scanResult || typeof scanResult !== "object") {
            return live
        }
        const isCompleted = !!(scanResult?.finishedAt || scanResult?.finished)
        if (!isCompleted || engineIsRunning) {
            return live
        }
        const existing = this._getStoredAnalysisContext(scanResult)
        const needsRefresh = !!force
            || !existing
            || existing.relatedScansSignature !== live.relatedScansSignature
            || existing.extraEnginesSignature !== live.extraEnginesSignature
        if (needsRefresh) {
            const snapshot = {
                relatedScans: deepClone(live.relatedScans),
                extraEnginesPresent: Array.isArray(live.extraEnginesPresent) ? live.extraEnginesPresent.slice() : [],
                relatedScansSignature: live.relatedScansSignature,
                extraEnginesSignature: live.extraEnginesSignature
            }
            this._setFrozenAnalysisContext(scanResult, snapshot)
            return snapshot
        }
        return {
            relatedScans: deepClone(existing.relatedScans || []),
            extraEnginesPresent: Array.isArray(existing.extraEnginesPresent) ? existing.extraEnginesPresent.slice() : [],
            relatedScansSignature: existing.relatedScansSignature || "",
            extraEnginesSignature: existing.extraEnginesSignature || ""
        }
    }

    deriveCrossEnginePresence({ scanResult = null, engineIsRunning = this.getEngineIsRunning() === true } = {}) {
        const engines = new Set()
        const currentScan = scanResult && typeof scanResult === "object"
            ? scanResult
            : (this.getCurrentScanResult?.() || null)
        const expectedHost = currentScan?.host || null
        if (this.isCompletedEngineScan(currentScan, { isRunning: engineIsRunning, expectedHost })) {
            engines.add("DAST")
        }
        const app = this.getAppState?.()
        if (!app || typeof app !== "object") {
            return Array.from(engines)
        }
        if (this.isCompletedEngineScan(app?.iast?.scanResult, { isRunning: app?.iast?.isScanRunning, expectedHost })) {
            engines.add("IAST")
        }
        if (this.isCompletedEngineScan(app?.sast?.scanResult, { isRunning: app?.sast?.isScanRunning, expectedHost })) {
            engines.add("SAST")
        }
        if (this.isCompletedEngineScan(app?.sca?.scanResult, { isRunning: app?.sca?.isScanRunning, expectedHost })) {
            engines.add("SCA")
        }
        return Array.from(engines)
    }

    normalizeRelatedScanCandidate(candidate, { expectedHost = null, engineFallback = null } = {}) {
        const envelope = this._unwrapStoredScan(candidate)
        if (!envelope || typeof envelope !== "object") return null
        if (!this.isCompletedEngineScan(envelope, { isRunning: false, expectedHost })) return null
        const engine = String(envelope?.engine || engineFallback || "").toUpperCase()
        if (!engine || engine === "DAST") return null
        if (!this.scanResultStore?.hydrateScan) {
            return envelope
        }
        const scanId = envelope?.scanId || envelope?.id || null
        if (scanId) {
            const existing = this.scanResultStore.getScan?.(scanId)
            if (existing && typeof existing === "object") {
                return this.ensureRelatedScanAnalysis(existing)
            }
        }
        const hydrated = this.scanResultStore.hydrateScan(envelope, { engineFallback: engine }) || envelope
        return this.ensureRelatedScanAnalysis(hydrated)
    }

    getRelatedScansFromApp(scanResult = this.getCurrentScanResult?.() || null) {
        const currentScan = scanResult && typeof scanResult === "object" ? scanResult : null
        const expectedHost = currentScan?.host || null
        const app = this.getAppState?.()
        if (!app || typeof app !== "object") return []
        const candidates = [
            { scan: app?.iast?.scanResult, engine: "IAST" },
            { scan: app?.sast?.scanResult, engine: "SAST" },
            { scan: app?.sca?.scanResult, engine: "SCA" }
        ]
        return candidates
            .map(({ scan, engine }) => this.normalizeRelatedScanCandidate(scan, {
                expectedHost,
                engineFallback: engine
            }))
            .filter(Boolean)
    }

    async hydratePersistedRelatedScans(scanResult = this.getCurrentScanResult?.() || null) {
        if (!this.storage?.getItem || !this.scanResultStore?.hydrateScan) return []
        const currentScan = scanResult && typeof scanResult === "object" ? scanResult : null
        const expectedHost = currentScan?.host || null
        const sources = [
            { engine: "IAST", storageKey: "ptk_iast" },
            { engine: "SAST", storageKey: "ptk_sast" },
            { engine: "SCA", storageKey: "ptk_sca" }
        ]
        const hydrated = []
        for (const source of sources) {
            try {
                const stored = await this.storage.getItem(source.storageKey)
                const envelope = this._unwrapStoredScan(stored)
                if (!envelope || typeof envelope !== "object") continue
                if (!this.isCompletedEngineScan(envelope, { isRunning: false, expectedHost })) continue
                const scanId = envelope?.scanId || envelope?.id || null
                if (scanId && this.scanResultStore.getScan(scanId)) {
                    hydrated.push(this.ensureRelatedScanAnalysis(this.scanResultStore.getScan(scanId)))
                    continue
                }
                const scan = this.scanResultStore.hydrateScan(envelope, { engineFallback: source.engine })
                if (scan) hydrated.push(this.ensureRelatedScanAnalysis(scan))
            } catch (_) { }
        }
        return hydrated
    }

    compactAnalysisForDiff(analysis) {
        if (!analysis || typeof analysis !== "object") return null
        const candidates = Array.isArray(analysis?.candidates) ? analysis.candidates : []
        return {
            version: analysis?.version || null,
            scanId: analysis?.scanId || null,
            candidates: candidates.map((candidate) => ({
                id: candidate?.id || null,
                suppressKey: candidate?.suppressKey || null,
                score: Number(candidate?.score || 0),
                confidence: candidate?.confidence || "low",
                confidenceRank: Number(candidate?.confidenceRank || 1),
                engineSignals: Array.isArray(candidate?.engineSignals) ? candidate.engineSignals : [],
                why: Array.isArray(candidate?.why) ? candidate.why : [],
                createdByRule: candidate?.createdByRule || null,
                routeKey: candidate?.routeKey || null,
                paramKey: candidate?.paramKey || null
            }))
        }
    }

    getPreviousAnalysisBase(scanResult) {
        if (!scanResult || typeof scanResult !== "object") return null
        const hostKey = this.normalizeAnalysisHostKey(scanResult?.host)
        if (!hostKey) return null
        const entry = this.diffBases?.[hostKey]
        if (!entry || typeof entry !== "object") return null
        if (String(entry?.scanId || "") === String(scanResult?.scanId || "")) return null
        return entry?.analysis && typeof entry.analysis === "object" ? entry.analysis : null
    }

    rememberAnalysisDiffBase(scanResult) {
        if (!scanResult || typeof scanResult !== "object") return
        if (!(scanResult?.finishedAt || scanResult?.finished)) return
        const hostKey = this.normalizeAnalysisHostKey(scanResult?.host)
        if (!hostKey) return
        const compact = this.compactAnalysisForDiff(scanResult?.analysis)
        if (!compact) return
        const existing = this.diffBases?.[hostKey]
        const currentScanId = String(scanResult?.scanId || "")
        const currentFinishedAt = String(scanResult?.finishedAt || scanResult?.finished || "")
        if (existing && String(existing?.scanId || "") === currentScanId && String(existing?.finishedAt || "") === currentFinishedAt) {
            return
        }
        if (!this.diffBases || typeof this.diffBases !== "object") {
            this.diffBases = {}
        }
        this.diffBases[hostKey] = {
            host: hostKey,
            scanId: currentScanId,
            finishedAt: currentFinishedAt,
            analysis: compact
        }
        this.storage?.setItem?.(this.diffBaseStorageKey, this.diffBases)
    }

    getSuppressionsForHost(host) {
        const hostKey = this.normalizeAnalysisHostKey(host)
        if (!hostKey) return []
        const entry = this.suppressions?.[hostKey]
        if (!entry) return []
        const list = Array.isArray(entry?.suppressions) ? entry.suppressions : []
        return Array.from(new Set(list.map((value) => String(value || "").trim()).filter(Boolean))).sort((a, b) => a.localeCompare(b))
    }

    setSuppression(host, suppressKey, suppressed = true) {
        const hostKey = this.normalizeAnalysisHostKey(host)
        const key = String(suppressKey || "").trim()
        if (!hostKey || !key) return this.getSuppressionsForHost(host)
        const existing = new Set(this.getSuppressionsForHost(hostKey))
        if (suppressed) {
            existing.add(key)
        } else {
            existing.delete(key)
        }
        const suppressions = Array.from(existing).sort((a, b) => a.localeCompare(b))
        if (!this.suppressions || typeof this.suppressions !== "object") {
            this.suppressions = {}
        }
        this.suppressions[hostKey] = {
            host: hostKey,
            suppressions,
            updatedAt: new Date().toISOString()
        }
        this.storage?.setItem?.(this.suppressionsStorageKey, this.suppressions)
        return suppressions
    }

    clearSuppressions(host) {
        const hostKey = this.normalizeAnalysisHostKey(host)
        if (!hostKey) return []
        if (!this.suppressions || typeof this.suppressions !== "object") {
            this.suppressions = {}
        }
        this.suppressions[hostKey] = {
            host: hostKey,
            suppressions: [],
            updatedAt: new Date().toISOString()
        }
        this.storage?.setItem?.(this.suppressionsStorageKey, this.suppressions)
        return []
    }

    clearHostState(host) {
        const hostKey = this.normalizeAnalysisHostKey(host)
        if (!hostKey) {
            return {
                host: "",
                diffBaseCleared: false,
                suppressionsCleared: false
            }
        }

        let diffBaseCleared = false
        if (this.diffBases && typeof this.diffBases === "object" && Object.prototype.hasOwnProperty.call(this.diffBases, hostKey)) {
            delete this.diffBases[hostKey]
            diffBaseCleared = true
            this.storage?.setItem?.(this.diffBaseStorageKey, this.diffBases)
        }

        let suppressionsCleared = false
        if (this.suppressions && typeof this.suppressions === "object" && Object.prototype.hasOwnProperty.call(this.suppressions, hostKey)) {
            delete this.suppressions[hostKey]
            suppressionsCleared = true
            this.storage?.setItem?.(this.suppressionsStorageKey, this.suppressions)
        }

        return {
            host: hostKey,
            diffBaseCleared,
            suppressionsCleared
        }
    }

    buildAnalysisOptions(scanResult = this.getCurrentScanResult?.() || null, { force = false, engineIsRunning = this.getEngineIsRunning() === true } = {}) {
        const stableInputs = this._resolveStableAnalysisInputs(scanResult, { force, engineIsRunning })
        return {
            force: !!force,
            extraEnginesPresent: stableInputs.extraEnginesPresent,
            previousAnalysis: this.getPreviousAnalysisBase(scanResult),
            relatedScans: stableInputs.relatedScans
        }
    }

    buildAnalysisMetadata(scanResult, { force = false, engineIsRunning = this.getEngineIsRunning() === true, relatedScans = [], extraEnginesPresent = [] } = {}) {
        const coverageEngines = Array.isArray(scanResult?.analysis?.coverage?.enginesPresent)
            ? scanResult.analysis.coverage.enginesPresent
            : []
        const relatedScansSignature = this._buildRelatedScansIdentitySignature(relatedScans)
        const extraEnginesSignature = (Array.isArray(extraEnginesPresent) ? extraEnginesPresent : []).join(",")
        const enginesPresent = Array.from(new Set([
            ...coverageEngines,
            ...(Array.isArray(extraEnginesPresent) ? extraEnginesPresent : [])
        ].map((engine) => String(engine || "").trim().toUpperCase()).filter(Boolean))).sort((a, b) => a.localeCompare(b))
        const relatedScanIds = (Array.isArray(relatedScans) ? relatedScans : [])
            .map((scan) => String(scan?.scanId || "").trim())
            .filter(Boolean)
            .sort((a, b) => a.localeCompare(b))
        let mode = "partial"
        if (engineIsRunning) {
            mode = "live"
        } else if (scanResult?.finishedAt || scanResult?.finished) {
            mode = "finalized"
        }
        return {
            computedAt: new Date().toISOString(),
            enginesPresent,
            relatedScanCount: relatedScanIds.length,
            relatedScanIds,
            relatedScansSignature,
            extraEnginesSignature,
            mode,
            forced: !!force
        }
    }

    getRelatedScansForCoverage(scanResult = this.getCurrentScanResult?.() || null) {
        if (!scanResult || typeof scanResult !== "object") return []
        const expectedHost = scanResult?.host || null
        const relatedFromStoreRaw = this.scanResultStore?.getRelatedScansForAnalysis?.({
            scanId: scanResult?.scanId || null,
            host: scanResult?.host || null,
            tabId: scanResult?.tabId,
            engine: scanResult?.engine || "DAST"
        }) || []
        const relatedFromStore = relatedFromStoreRaw
            .map((scan) => this.normalizeRelatedScanCandidate(scan, {
                expectedHost,
                engineFallback: scan?.engine || null
            }))
            .filter(Boolean)
        const relatedFromApp = this.getRelatedScansFromApp(scanResult)
        const merged = new Map()
        ;[...relatedFromStore, ...relatedFromApp].forEach((scan) => {
            if (!scan || typeof scan !== "object") return
            const key = String(scan?.scanId || `${scan?.engine || "ENGINE"}:${scan?.finishedAt || scan?.startedAt || ""}`)
            if (!merged.has(key)) {
                merged.set(key, scan)
            }
        })
        return Array.from(merged.values())
    }

    applyMergedCoverage(scanResult, { relatedScans = null } = {}) {
        if (!scanResult || typeof scanResult !== "object") return scanResult
        const analysis = scanResult.analysis && typeof scanResult.analysis === "object"
            ? scanResult.analysis
            : (scanResult.analysis = {})
        analysis.coverage = buildHostCoverageAnalysis({
            primaryScan: scanResult,
            primaryCoverage: analysis.coverage || {},
            relatedScans: Array.isArray(relatedScans) ? relatedScans : this.getRelatedScansForCoverage(scanResult)
        })
        return scanResult
    }

    applyAnalysis(scanResult, { force = false, engineIsRunning = this.getEngineIsRunning() === true } = {}) {
        if (!scanResult || typeof scanResult !== "object") return scanResult
        if (!force && !engineIsRunning && this.hasCurrentAnalysis(scanResult)) {
            const storedContext = this._getStoredAnalysisContext(scanResult)
            if (storedContext) {
                const liveInputs = this._buildLiveAnalysisInputs(scanResult, { engineIsRunning })
                if (
                    storedContext.relatedScansSignature === liveInputs.relatedScansSignature
                    && storedContext.extraEnginesSignature === liveInputs.extraEnginesSignature
                ) {
                    return scanResult
                }
            }
        }
        const options = this.buildAnalysisOptions(scanResult, { force, engineIsRunning })
        applyScanAnalysis(scanResult, options)
        this.applyMergedCoverage(scanResult, { relatedScans: options.relatedScans })
        if (!scanResult.analysis || typeof scanResult.analysis !== "object") {
            scanResult.analysis = {}
        }
        scanResult.analysis.meta = this.buildAnalysisMetadata(scanResult, {
            force,
            engineIsRunning,
            relatedScans: options.relatedScans,
            extraEnginesPresent: options.extraEnginesPresent
        })
        this.rememberAnalysisDiffBase(scanResult)
        return scanResult
    }
}

export default DastAnalysisService
