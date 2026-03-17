import { applyScanAnalysis } from "../../analysis/scanAnalysisEngine.js"
import { buildHostCoverageAnalysis } from "../../analysis/hostCoverageAnalysis.js"

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

    getRelatedScansFromApp(scanResult = this.getCurrentScanResult?.() || null) {
        const currentScan = scanResult && typeof scanResult === "object" ? scanResult : null
        const expectedHost = currentScan?.host || null
        const app = this.getAppState?.()
        if (!app || typeof app !== "object") return []
        const candidates = [
            app?.iast?.scanResult,
            app?.sast?.scanResult,
            app?.sca?.scanResult
        ]
        return candidates.filter((candidate) => {
            if (!candidate || typeof candidate !== "object") return false
            const engine = String(candidate?.engine || "").toUpperCase()
            if (!engine || engine === "DAST") return false
            return this.isCompletedEngineScan(candidate, {
                isRunning: false,
                expectedHost
            })
        })
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
                    hydrated.push(this.scanResultStore.getScan(scanId))
                    continue
                }
                const scan = this.scanResultStore.hydrateScan(envelope, { engineFallback: source.engine })
                if (scan) hydrated.push(scan)
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

    buildAnalysisOptions(scanResult = this.getCurrentScanResult?.() || null, { force = false, engineIsRunning = this.getEngineIsRunning() === true } = {}) {
        return {
            force: !!force,
            extraEnginesPresent: this.deriveCrossEnginePresence({ scanResult, engineIsRunning }),
            previousAnalysis: this.getPreviousAnalysisBase(scanResult)
        }
    }

    getRelatedScansForCoverage(scanResult = this.getCurrentScanResult?.() || null) {
        if (!scanResult || typeof scanResult !== "object") return []
        const relatedFromStore = this.scanResultStore?.getRelatedScansForAnalysis?.({
            scanId: scanResult?.scanId || null,
            host: scanResult?.host || null,
            tabId: scanResult?.tabId,
            engine: scanResult?.engine || "DAST"
        }) || []
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

    applyMergedCoverage(scanResult) {
        if (!scanResult || typeof scanResult !== "object") return scanResult
        const analysis = scanResult.analysis && typeof scanResult.analysis === "object"
            ? scanResult.analysis
            : (scanResult.analysis = {})
        analysis.coverage = buildHostCoverageAnalysis({
            primaryScan: scanResult,
            primaryCoverage: analysis.coverage || {},
            relatedScans: this.getRelatedScansForCoverage(scanResult)
        })
        return scanResult
    }

    applyAnalysis(scanResult, { force = false, engineIsRunning = this.getEngineIsRunning() === true } = {}) {
        if (!scanResult || typeof scanResult !== "object") return scanResult
        applyScanAnalysis(scanResult, this.buildAnalysisOptions(scanResult, { force, engineIsRunning }))
        this.applyMergedCoverage(scanResult)
        this.rememberAnalysisDiffBase(scanResult)
        return scanResult
    }
}

export default DastAnalysisService
