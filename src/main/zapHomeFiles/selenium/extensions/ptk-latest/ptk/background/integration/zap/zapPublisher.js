'use strict'

import { toAlert } from './zapMapper.js'
import { toDastFinding } from './zapDastMapper.js'
import { toIastFinding } from './zapIastMapper.js'
import { toSastFinding } from './zapSastMapper.js'
import { isZapExportableFinding } from './zapFindingFilter.js'

const ENGINES = ['DAST', 'IAST', 'SAST']
const POLL_INTERVAL_MS = 2000
const ALERT_CHUNK_SIZE = 200
const MAX_KEYS = 50
const KEY_IDLE_EVICT_MS = 10 * 60 * 1000
const PUBLISHED_STATE_CAP_PER_KEY = 5000

function chunkArray(items, size) {
    if (!Array.isArray(items) || !items.length) return []
    const chunks = []
    for (let i = 0; i < items.length; i += size) {
        chunks.push(items.slice(i, i + size))
    }
    return chunks
}

function stableStringify(value) {
    if (value === null || value === undefined) return 'null'
    if (typeof value === 'string') return JSON.stringify(value)
    if (typeof value === 'number' || typeof value === 'boolean') return String(value)
    if (Array.isArray(value)) {
        return `[${value.map((entry) => stableStringify(entry)).join(',')}]`
    }
    if (typeof value === 'object') {
        return `{${Object.keys(value).sort((a, b) => a.localeCompare(b)).map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`
    }
    return JSON.stringify(String(value))
}

export default class ZapPublisher {
    constructor(app, zapBridge, resultsRegistry) {
        this.app = app
        this.zapBridge = zapBridge
        this.resultsRegistry = resultsRegistry

        this.timerId = null
        this.pollInFlight = false
        this.wasActive = false
        this.disabled = false
        this.apiValidated = false
        this.missingApiWarned = false

        this.publishedState = new Map()
        this.lastSeen = new Map()
    }

    start() {
        if (this.timerId || this.disabled) return
        void this._pollOnce()
        this.timerId = setInterval(() => {
            void this._pollOnce()
        }, POLL_INTERVAL_MS)
    }

    stop() {
        if (!this.timerId) return
        clearInterval(this.timerId)
        this.timerId = null
    }

    resetState() {
        this.publishedState.clear()
        this.lastSeen.clear()
        this.wasActive = false
    }

    _disablePublisher() {
        this.disabled = true
        this.stop()
    }

    _validateRegistryApi() {
        if (this.apiValidated) {
            return !this.disabled
        }

        this.apiValidated = true
        const hasFindScanIdForEngine = typeof this.resultsRegistry?.findScanIdForEngine === 'function'
        const hasGet = typeof this.resultsRegistry?.get === 'function'

        if (!hasFindScanIdForEngine || !hasGet) {
            if (!this.missingApiWarned) {
                console.warn('[PTK ZAP] resultsRegistry API missing required methods; publisher disabled')
                this.missingApiWarned = true
            }
            this._disablePublisher()
            return false
        }

        return true
    }

    async _pollOnce() {
        if (this.disabled || this.pollInFlight) return
        this.pollInFlight = true

        try {
            await this._runPoll()
        } catch (err) {
            console.warn('[PTK ZAP] Poll cycle failed:', err)
        } finally {
            this.pollInFlight = false
        }
    }

    async _runPoll() {
        if (!this._validateRegistryApi()) return

        const active = this.zapBridge.isActive()
        if (active && !this.wasActive) {
            this.resetState()
        }
        this.wasActive = active

        if (!active) return

        for (const engine of ENGINES) {
            await this._pollEngine(engine)
        }

        this._evictStaleKeys()
    }

    async _pollEngine(engine) {
        try {
            const host = typeof this.zapBridge?.getActiveTargetHost === 'function'
                ? this.zapBridge.getActiveTargetHost()
                : null
            const scanId = await this.resultsRegistry.findScanIdForEngine(engine, {
                host: host || null
            })
            if (!scanId) return

            const scanResult = await this.resultsRegistry.get(engine, scanId)
            if (!scanResult) return

            const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
            const key = `${engine}:${scanId}`
            this._touchKey(key)
            if (engine === 'DAST') {
                await this._publishDastFindings({
                    key,
                    scanId,
                    scanResult,
                    findings
                })
                return
            }

            if (engine === 'IAST') {
                await this._publishEngineFindingsBatch({
                    key,
                    engine,
                    scanId,
                    findings,
                    mapper: toIastFinding,
                    sender: (payload) => this.zapBridge.sendIastFindingsBatch(payload)
                })
                return
            }

            if (engine === 'SAST') {
                await this._publishEngineFindingsBatch({
                    key,
                    engine,
                    scanId,
                    findings,
                    mapper: toSastFinding,
                    sender: (payload) => this.zapBridge.sendSastFindingsBatch(payload)
                })
                return
            }

            const alerts = []

            for (const finding of findings) {
                const alert = toAlert(finding, { engine, scanId })
                if (!alert) continue
                const findingKey = this._getMappedFindingKey(alert)
                const signature = stableStringify(alert)
                if (!this._shouldPublishFindingVersion(key, findingKey, signature)) {
                    continue
                }
                alerts.push({ mapped: alert, findingKey, signature })
            }

            if (!alerts.length) return

            const chunks = chunkArray(alerts, ALERT_CHUNK_SIZE)
            for (const chunk of chunks) {
                try {
                    await this.zapBridge.sendAlertsBatch({
                        engine,
                        scanId,
                        alerts: chunk.map((entry) => entry.mapped),
                        truncated: false
                    })
                    chunk.forEach((entry) => this._markFindingVersionPublished(key, entry.findingKey, entry.signature))
                } catch (err) {
                    console.warn('[PTK ZAP] Failed to send alerts chunk; dropping chunk', {
                        engine,
                        scanId,
                        error: err?.message || String(err)
                    })
                }
            }
        } catch (err) {
            console.warn('[PTK ZAP] Engine publish iteration failed', {
                engine,
                error: err?.message || String(err)
            })
        }
    }

    async _publishDastFindings({ key, scanId, scanResult, findings: sourceFindings }) {
        const findings = []
        let skippedFilter = 0
        let skippedMapper = 0

        for (const finding of sourceFindings) {
            if (!isZapExportableFinding('DAST', finding)) {
                skippedFilter += 1
                continue
            }

            const mapped = toDastFinding(finding, {
                scanId,
                scanResult
            })
            if (!mapped) {
                skippedMapper += 1
                continue
            }
            const findingKey = this._getMappedFindingKey(mapped)
            const signature = stableStringify(mapped)
            if (!this._shouldPublishFindingVersion(key, findingKey, signature)) {
                continue
            }
            findings.push({ mapped, findingKey, signature })
        }

        if (!findings.length) return

        this.zapBridge?._debugLog?.('[PTK ZAP] Publish stats:', {
            engine: 'DAST',
            scanId,
            total: Array.isArray(sourceFindings) ? sourceFindings.length : 0,
            exportable: (Array.isArray(sourceFindings) ? sourceFindings.length : 0) - skippedFilter,
            mapped: findings.length,
            skippedFilter,
            skippedMapper
        })

        const chunks = chunkArray(findings, ALERT_CHUNK_SIZE)
        for (const chunk of chunks) {
            try {
                await this.zapBridge.sendDastFindingsBatch({
                    scanId,
                    findings: chunk.map((entry) => entry.mapped),
                    truncated: false
                })
                chunk.forEach((entry) => this._markFindingVersionPublished(key, entry.findingKey, entry.signature))
            } catch (err) {
                console.warn('[PTK ZAP] Failed to send DAST findings chunk; dropping chunk', {
                    engine: 'DAST',
                    scanId,
                    error: err?.message || String(err)
                })
            }
        }
    }

    async _publishEngineFindingsBatch({ key, engine, scanId, findings: sourceFindings, mapper, sender }) {
        const findings = []
        let skippedFilter = 0
        let skippedMapper = 0

        for (const finding of sourceFindings) {
            if (!isZapExportableFinding(engine, finding)) {
                skippedFilter += 1
                continue
            }

            const mapped = mapper(finding, { scanId })
            if (!mapped) {
                skippedMapper += 1
                continue
            }
            const findingKey = this._getMappedFindingKey(mapped)
            const signature = stableStringify(mapped)
            if (!this._shouldPublishFindingVersion(key, findingKey, signature)) {
                continue
            }
            findings.push({ mapped, findingKey, signature })
        }

        if (!findings.length) return

        this.zapBridge?._debugLog?.('[PTK ZAP] Publish stats:', {
            engine,
            scanId,
            total: Array.isArray(sourceFindings) ? sourceFindings.length : 0,
            exportable: (Array.isArray(sourceFindings) ? sourceFindings.length : 0) - skippedFilter,
            mapped: findings.length,
            skippedFilter,
            skippedMapper
        })

        const chunks = chunkArray(findings, ALERT_CHUNK_SIZE)
        for (const chunk of chunks) {
            try {
                await sender({
                    scanId,
                    findings: chunk.map((entry) => entry.mapped),
                    truncated: false
                })
                chunk.forEach((entry) => this._markFindingVersionPublished(key, entry.findingKey, entry.signature))
            } catch (err) {
                console.warn('[PTK ZAP] Failed to send findings chunk; dropping chunk', {
                    engine,
                    scanId,
                    error: err?.message || String(err)
                })
            }
        }
    }

    _touchKey(key) {
        this.lastSeen.set(key, Date.now())
    }

    _getPublishedStateForKey(key) {
        if (!this.publishedState.has(key)) {
            this.publishedState.set(key, new Map())
        }
        return this.publishedState.get(key)
    }

    _getMappedFindingKey(mapped) {
        const fingerprint = typeof mapped?.fingerprint === 'string' ? mapped.fingerprint.trim() : ''
        if (fingerprint) return fingerprint
        const id = typeof mapped?.id === 'string' ? mapped.id.trim() : ''
        if (id) return id
        return stableStringify(mapped)
    }

    _shouldPublishFindingVersion(key, findingKey, signature) {
        const state = this._getPublishedStateForKey(key)
        return state.get(findingKey) !== signature
    }

    _markFindingVersionPublished(key, findingKey, signature) {
        if (!findingKey) return
        const state = this._getPublishedStateForKey(key)
        if (state.has(findingKey)) {
            state.delete(findingKey)
        }
        state.set(findingKey, signature)

        while (state.size > PUBLISHED_STATE_CAP_PER_KEY) {
            const oldestKey = state.keys().next().value
            state.delete(oldestKey)
        }
    }

    _evictStaleKeys() {
        const now = Date.now()

        for (const [key, lastSeenAt] of this.lastSeen.entries()) {
            if (now - lastSeenAt > KEY_IDLE_EVICT_MS) {
                this._dropKey(key)
            }
        }

        while (this.publishedState.size > MAX_KEYS) {
            const oldest = [...this.lastSeen.entries()].sort((a, b) => a[1] - b[1])[0]
            if (!oldest) break
            this._dropKey(oldest[0])
        }
    }

    _dropKey(key) {
        this.lastSeen.delete(key)
        this.publishedState.delete(key)
    }
}
