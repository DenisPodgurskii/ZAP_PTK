import { scanResultStore } from './scanResultStore.js'

function normalizeHostKey(host) {
    if (host === undefined || host === null) return ''
    return String(host).trim().toLowerCase()
}

function toTimestamp(value) {
    if (!value) return 0
    const ts = Date.parse(String(value))
    return Number.isFinite(ts) ? ts : 0
}

/**
 * Central abstraction for accessing scan results.
 * Decouples export logic from internal engine shapes.
 *
 * Resolution order:
 * 1. scanResultStore (IAST, SAST use this) - in-memory Map
 * 2. In-memory engine scanResult (DAST, SCA fallback)
 */
class ResultsRegistry {
    constructor() {
        this.app = null
    }

    init(app) {
        this.app = app
    }

    /**
     * Get scan result by engine and scanId
     * @param {string} engine - DAST, IAST, SAST, SCA
     * @param {string} scanId - Engine-specific scan ID
     * @returns {Object|null} Scan result or null
     */
    get(engine, scanId) {
        if (!scanId) return null

        const stored = scanResultStore.getScan(scanId)
        if (stored) return stored

        return this._getFromEngine(engine, scanId)
    }

    _getFromEngine(engine, scanId) {
        const engineUpper = String(engine || '').toUpperCase()

        const sources = {
            DAST: () => this.app?.dast?.scanResult || this.app?.rattacker?.scanResult,
            IAST: () => this.app?.iast?.scanResult || (this.app?.iast?.currentScanId ? { scanId: this.app.iast.currentScanId } : null),
            SAST: () => this.app?.sast?.scanResult,
            SCA: () => this.app?.sca?.scanResult
        }

        const getter = sources[engineUpper]
        const result = getter?.()

        if (result?.scanId === scanId) {
            return result
        }

        return null
    }

    findScanIdForEngine(engine, hints = {}) {
        const ids = this.findScanIdsForEngine(engine, { ...hints, latestFirst: true })
        return ids[0] || null
    }

    findScanIdsForEngine(engine, hints = {}) {
        const engineUpper = String(engine || '').toUpperCase()
        const storedScanIds = typeof scanResultStore.findScanIds === 'function'
            ? scanResultStore.findScanIds({
                engine: engineUpper,
                host: hints?.host || null,
                tabId: hints?.tabId,
                startedAfterMs: hints?.startedAfterMs,
                latestFirst: hints?.latestFirst === true
            })
            : []
        const scanIds = Array.isArray(storedScanIds) ? storedScanIds.slice() : []

        const fallbackId = this._findFallbackScanIdForEngine(engineUpper, hints)
        if (fallbackId && !scanIds.includes(fallbackId)) {
            scanIds.push(fallbackId)
        }

        return scanIds
    }

    _findFallbackScanIdForEngine(engineUpper, hints = {}) {
        const sources = {
            DAST: () => this.app?.dast?.scanResult || this.app?.rattacker?.scanResult,
            IAST: () => this.app?.iast?.scanResult || (this.app?.iast?.currentScanId ? { scanId: this.app.iast.currentScanId } : null),
            SAST: () => this.app?.sast?.scanResult,
            SCA: () => this.app?.sca?.scanResult
        }

        const getter = sources[engineUpper]
        const scan = getter?.()
        if (!scan?.scanId) return null

        const hostKey = normalizeHostKey(hints?.host)
        if (hostKey && scan.host && normalizeHostKey(scan.host) !== hostKey) return null

        const hasTabHint = hints?.tabId !== undefined && hints?.tabId !== null
        if (hasTabHint && scan.tabId !== undefined && scan.tabId !== null && scan.tabId !== hints.tabId) {
            return null
        }

        const startedAfterMs = Number(hints?.startedAfterMs)
        const startedAt = toTimestamp(scan.startedAt || null)
        if (Number.isFinite(startedAfterMs) && startedAfterMs > 0 && startedAt > 0 && startedAt < startedAfterMs) {
            return null
        }

        return scan.scanId
    }

    findLatestScanIdForEngine(engine, hints = {}) {
        return this.findScanIdForEngine(engine, hints)
    }

    findLatestStoredScanIdForEngine(engine, hints = {}) {
        const engineUpper = String(engine || '').toUpperCase()
        return scanResultStore.findLatestScanId({
            engine: engineUpper,
            host: hints?.host || null,
            tabId: hints?.tabId
        })
    }
}

export const resultsRegistry = new ResultsRegistry()
export default resultsRegistry
