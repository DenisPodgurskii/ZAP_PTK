import { scanResultStore } from "../../scanResultStore.js"
import buildExportScanResult from "../../export/buildExportScanResult.js"
import { getCompletedDastAnalysis, markPersistedDastAnalysis, preparePersistedDastAnalysis, stripPrivateDastAnalysisMetadata } from "./dastAnalysisService.js"

function cloneValue(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value ?? null
    }
}

export class DastScanResultLifecycleService {
    constructor({
        storage = null,
        storageKey = "ptk_rattacker",
        scanStore = scanResultStore,
        buildExport = buildExportScanResult
    } = {}) {
        this.storage = storage
        this.storageKey = storageKey
        this.scanStore = scanStore
        this.buildExport = buildExport
        this._activePersist = null
        this._pendingPersist = null
    }

    normalizeImportedScan(raw) {
        if (!raw || typeof raw !== "object") return null
        const clone = cloneValue(raw)
        if (clone?.scanResult && typeof clone.scanResult === "object") {
            return clone.scanResult
        }
        if (clone?.engine && Array.isArray(clone.requests)) {
            return clone
        }
        if (!clone?.type || String(clone.type).toLowerCase() === "dast") {
            const items = Array.isArray(clone.items) ? clone.items : []
            if (items.length) {
                return clone
            }
        }
        return null
    }

    syncScanResult(scanResult, { markFinished = false } = {}) {
        if (!scanResult || typeof scanResult !== "object") return null
        const scanId = scanResult.scanId || null
        if (!scanId) {
            return cloneValue(scanResult)
        }
        const hydrated = this.scanStore?.hydrateScan?.(scanResult, { engineFallback: "DAST" }) || null
        const finishedAt = scanResult.finishedAt || scanResult.finished || null
        if ((markFinished || finishedAt) && hydrated && typeof hydrated === "object") {
            hydrated.finishedAt = finishedAt || new Date().toISOString()
        }
        return this.scanStore?.getScan?.(scanId) || hydrated || cloneValue(scanResult)
    }

    exportScanSnapshot(scanResult, { sync = true, markFinished = false, dropTabId = false } = {}) {
        if (!scanResult || typeof scanResult !== "object") return null
        const scanId = scanResult.scanId || null
        let syncedScan = scanResult
        if (sync) {
            syncedScan = this.syncScanResult(scanResult, { markFinished }) || scanResult
        }
        const source = scanId
            ? cloneValue(this.scanStore?.getScan?.(scanId) || syncedScan || scanResult)
            : cloneValue(syncedScan || scanResult)
        if (!source || typeof source !== "object") return source
        if (dropTabId) {
            delete source.tabId
        }
        return source
    }

    cloneForStorage(scanResult, { dropTabId = true } = {}) {
        const prepared = getCompletedDastAnalysis(scanResult)
        const source = prepared ? scanResult : this.exportScanSnapshot(scanResult, {
            sync: true,
            markFinished: !!(scanResult?.finishedAt || scanResult?.finished),
            dropTabId
        }) || {}
        const cloned = cloneValue(source) || {}
        if (dropTabId && cloned && typeof cloned === "object") {
            delete cloned.tabId
        }
        if (Array.isArray(cloned?.rawFindings)) {
            delete cloned.rawFindings
        }
        if (!prepared) stripPrivateDastAnalysisMetadata(cloned.analysis)
        return preparePersistedDastAnalysis(scanResult, cloned)
    }

    persistScanResult(scanResult, { dropTabId = true, isCurrent = null } = {}) {
        const cloned = this.cloneForStorage(scanResult, { dropTabId })
        if (this._pendingPersist) {
            // Autosave already coalesces on a debounce. If storage itself stalls,
            // retain only the latest pending snapshot, not an unbounded tail.
            this._pendingPersist.snapshot = cloned
            this._pendingPersist.isCurrent = isCurrent
            return this._pendingPersist.promise
        }
        let resolve, reject
        const promise = new Promise((yes, no) => { resolve = yes; reject = no })
        const job = { snapshot: cloned, isCurrent, promise, resolve, reject }
        if (this._activePersist) this._pendingPersist = job
        else this._startPersist(job)
        return promise
    }

    _startPersist(job) {
        this._activePersist = job
        const write = async () => {
            if (job.isCurrent && !job.isCurrent()) return null
            await this.storage?.setItem?.(this.storageKey, job.snapshot)
            return job.snapshot
        }
        const finish = () => {
            this._activePersist = null
            const next = this._pendingPersist
            this._pendingPersist = null
            if (next) this._startPersist(next)
        }
        write().then(value => { finish(); job.resolve(value) }, error => { finish(); job.reject(error) })
    }

    async loadPersistedScan() {
        if (!this.storage?.getItem) return null
        const stored = await this.storage.getItem(this.storageKey)
        return markPersistedDastAnalysis(this.hydrateImportedScan(stored))
    }

    hydrateImportedScan(raw) {
        const normalized = this.normalizeImportedScan(raw)
        if (!normalized) return null
        this.syncScanResult(normalized, { markFinished: !!(normalized.finishedAt || normalized.finished) })
        return this.exportScanSnapshot(normalized, {
            sync: false,
            markFinished: !!(normalized.finishedAt || normalized.finished)
        })
    }

    buildExportPayload(scanResult, { target = "download", includeSecrets = false } = {}) {
        if (!scanResult || typeof scanResult !== "object") return null
        if (getCompletedDastAnalysis(scanResult)) {
            return this.buildExport(scanResult.scanId, { target, includeSecrets: includeSecrets === true, scanResult })
        }
        const source = this.exportScanSnapshot(scanResult, {
            sync: true,
            markFinished: !!(scanResult.finishedAt || scanResult.finished)
        })
        if (!source) return null
        const scanId = source.scanId || scanResult.scanId || null
        return this.buildExport(scanId, {
            target,
            includeSecrets: includeSecrets === true,
            scanResult: source
        })
    }

    deleteScan(scanId) {
        if (!scanId) return
        this.scanStore?.deleteScan?.(scanId)
    }
}

export default DastScanResultLifecycleService
