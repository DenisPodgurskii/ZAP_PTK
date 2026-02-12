'use strict'

import zapTransport from './zapTransport.js'
import ZapPublisher from './zapPublisher.js'

const SOURCE = 'ptk'
const TYPE_ALERTS_BATCH = 'alerts_batch'

function createBatchId() {
    if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
        return globalThis.crypto.randomUUID()
    }
    return `ptk-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`
}

class ZapBridge {
    constructor() {
        this.transport = zapTransport
        this.publisher = null
        this.app = null
        this.resultsRegistry = null
        this.initialized = false
        this.currentBaseUrl = null
        this._unsubscribeDetected = null
    }

    init(app, resultsRegistry) {
        this.app = app || this.app
        this.resultsRegistry = resultsRegistry || this.resultsRegistry

        if (this.app && this.resultsRegistry && !this.publisher) {
            this.publisher = new ZapPublisher(this.app, this, this.resultsRegistry)
        } else if (this.publisher) {
            this.publisher.app = this.app
            this.publisher.resultsRegistry = this.resultsRegistry
        }

        if (this.initialized) return

        this._unsubscribeDetected = this.transport.onZapDetected((payload) => {
            this._handleZapDetected(payload)
        })
        this.transport.init()
        this.initialized = true
    }

    start() {
        if (!this.publisher) return
        this.publisher.start()
    }

    isActive() {
        return this.transport.isActive()
    }

    async sendAlertsBatch({ engine, scanId, alerts, truncated }) {
        if (!this.isActive()) return
        if (!Array.isArray(alerts) || alerts.length === 0) return

        const envelope = {
            source: SOURCE,
            type: TYPE_ALERTS_BATCH,
            ts: Date.now(),
            batchId: createBatchId(),
            payload: {
                sessionId: null,
                engine: engine || null,
                scanId: scanId || null,
                alerts,
                truncated: truncated === true
            }
        }

        await this.transport.postJson(envelope)
    }

    _handleZapDetected(payload = {}) {
        const baseUrl = payload.baseUrl || this.transport.getBaseUrl()
        const isNewBaseUrl = !!baseUrl && baseUrl !== this.currentBaseUrl
        this.currentBaseUrl = baseUrl || this.currentBaseUrl

        this.start()

        if (this.publisher && isNewBaseUrl) {
            this.publisher.resetState()
        }
    }
}

const zapBridge = new ZapBridge()

export default zapBridge
