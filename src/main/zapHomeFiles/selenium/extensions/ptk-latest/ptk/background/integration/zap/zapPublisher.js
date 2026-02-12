'use strict'

import { toAlert } from './zapMapper.js'

const ENGINES = ['DAST', 'IAST', 'SAST', 'SCA']
const POLL_INTERVAL_MS = 4000
const ALERT_CHUNK_SIZE = 200
const MAX_KEYS = 50
const KEY_IDLE_EVICT_MS = 10 * 60 * 1000
const DEDUPE_CAP_PER_KEY = 5000

function chunkArray(items, size) {
    if (!Array.isArray(items) || !items.length) return []
    const chunks = []
    for (let i = 0; i < items.length; i += size) {
        chunks.push(items.slice(i, i + size))
    }
    return chunks
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

        this.lastLen = new Map()
        this.dedupeSet = new Map()
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
        this.lastLen.clear()
        this.dedupeSet.clear()
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
            const scanId = await this.resultsRegistry.findScanIdForEngine(engine)
            if (!scanId) return

            const scanResult = await this.resultsRegistry.get(engine, scanId)
            if (!scanResult) return

            const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
            const key = `${engine}:${scanId}`
            this._touchKey(key)

            let startIndex = this.lastLen.get(key) || 0
            if (findings.length < startIndex) {
                startIndex = 0
                this.lastLen.set(key, 0)
            }

            const deltaFindings = findings.slice(startIndex)
            this.lastLen.set(key, findings.length)

            if (!deltaFindings.length) return

            const dedupe = this._getDedupeForKey(key)
            const alerts = []

            for (const finding of deltaFindings) {
                const alert = toAlert(finding, { engine, scanId })
                if (!alert) continue

                const fingerprint = typeof alert.fingerprint === 'string' ? alert.fingerprint : null
                if (fingerprint && dedupe.has(fingerprint)) {
                    continue
                }

                if (fingerprint) {
                    this._rememberFingerprint(dedupe, fingerprint)
                }

                alerts.push(alert)
            }

            if (!alerts.length) return

            const chunks = chunkArray(alerts, ALERT_CHUNK_SIZE)
            for (const chunk of chunks) {
                try {
                    await this.zapBridge.sendAlertsBatch({
                        engine,
                        scanId,
                        alerts: chunk,
                        truncated: false
                    })
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

    _touchKey(key) {
        this.lastSeen.set(key, Date.now())
    }

    _getDedupeForKey(key) {
        if (!this.dedupeSet.has(key)) {
            this.dedupeSet.set(key, new Map())
        }
        return this.dedupeSet.get(key)
    }

    _rememberFingerprint(dedupe, fingerprint) {
        if (!fingerprint) return
        if (dedupe.has(fingerprint)) {
            dedupe.delete(fingerprint)
        }
        dedupe.set(fingerprint, true)

        while (dedupe.size > DEDUPE_CAP_PER_KEY) {
            const oldestFingerprint = dedupe.keys().next().value
            dedupe.delete(oldestFingerprint)
        }
    }

    _evictStaleKeys() {
        const now = Date.now()

        for (const [key, lastSeenAt] of this.lastSeen.entries()) {
            if (now - lastSeenAt > KEY_IDLE_EVICT_MS) {
                this._dropKey(key)
            }
        }

        while (this.lastLen.size > MAX_KEYS) {
            const oldest = [...this.lastSeen.entries()].sort((a, b) => a[1] - b[1])[0]
            if (!oldest) break
            this._dropKey(oldest[0])
        }
    }

    _dropKey(key) {
        this.lastLen.delete(key)
        this.lastSeen.delete(key)
        this.dedupeSet.delete(key)
    }
}
