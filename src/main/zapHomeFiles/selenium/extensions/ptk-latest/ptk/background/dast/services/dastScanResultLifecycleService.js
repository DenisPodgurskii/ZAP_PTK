import { scanResultStore } from "../../scanResultStore.js"
import buildExportScanResult from "../../export/buildExportScanResult.js"

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
        if ((markFinished || finishedAt) && this.scanStore?.setFinished) {
            this.scanStore.setFinished(scanId, finishedAt || new Date().toISOString())
        }
        return this.scanStore?.getScan?.(scanId) || hydrated || cloneValue(scanResult)
    }

    exportScanSnapshot(scanResult, { sync = true, markFinished = false, dropTabId = false } = {}) {
        if (!scanResult || typeof scanResult !== "object") return null
        const scanId = scanResult.scanId || null
        if (sync) {
            this.syncScanResult(scanResult, { markFinished })
        }
        const source = scanId && this.scanStore?.exportScanResult
            ? this.scanStore.exportScanResult(scanId)
            : cloneValue(scanResult)
        if (!source || typeof source !== "object") return source
        if (dropTabId) {
            delete source.tabId
        }
        return source
    }

    cloneForStorage(scanResult, { dropTabId = true } = {}) {
        const source = this.exportScanSnapshot(scanResult, {
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
        return cloned
    }

    async persistScanResult(scanResult, { dropTabId = true } = {}) {
        const cloned = this.cloneForStorage(scanResult, { dropTabId })
        if (this.storage?.setItem) {
            await this.storage.setItem(this.storageKey, cloned)
        }
        return cloned
    }

    async loadPersistedScan() {
        if (!this.storage?.getItem) return null
        const stored = await this.storage.getItem(this.storageKey)
        return this.hydrateImportedScan(stored)
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

    buildExportPayload(scanResult, { target = "download" } = {}) {
        if (!scanResult || typeof scanResult !== "object") return null
        const source = this.exportScanSnapshot(scanResult, {
            sync: true,
            markFinished: !!(scanResult.finishedAt || scanResult.finished)
        })
        if (!source) return null
        const scanId = source.scanId || scanResult.scanId || null
        return this.buildExport(scanId, {
            target,
            scanResult: source
        })
    }

    deleteScan(scanId) {
        if (!scanId) return
        this.scanStore?.deleteScan?.(scanId)
    }
}

export default DastScanResultLifecycleService
