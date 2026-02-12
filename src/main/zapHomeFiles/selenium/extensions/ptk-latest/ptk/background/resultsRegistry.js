import { scanResultStore } from './scanResultStore.js'

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
            DAST: () => this.app?.rattacker?.scanResult,
            IAST: () => this.app?.iast?.scanResult,
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

    /**
     * Best-effort scanId lookup from in-memory engine state.
     * Does NOT search scanResultStore (would need index by engine/host).
     */
    findScanIdForEngine(engine, hints = {}) {
        const engineUpper = String(engine || '').toUpperCase()

        const sources = {
            DAST: () => this.app?.rattacker?.scanResult?.scanId,
            IAST: () => this.app?.iast?.scanResult?.scanId || this.app?.iast?.currentScanId,
            SAST: () => this.app?.sast?.scanResult?.scanId,
            SCA: () => this.app?.sca?.scanResult?.scanId
        }

        const getter = sources[engineUpper]
        return getter?.() || null
    }
}

export const resultsRegistry = new ResultsRegistry()
export default resultsRegistry
