'use strict'

const DETECTION_REGEX = /^https:\/\/zap\/zapCallBackUrl\/([^/?#]+)/i
const RETRY_DELAYS_MS = [250, 1000, 4000]

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms))
}

class ZapTransport {
    constructor() {
        this.secret = null
        this.baseUrl = null
        this.active = false
        this._detectedCallbacks = new Set()
        this._listenerAttached = false
        this._onCommitted = null
    }

    init() {
        if (this._listenerAttached) return

        if (!browser?.webNavigation?.onCommitted) {
            console.warn('[PTK ZAP] webNavigation API not available')
            return
        }

        this._onCommitted = this._onCommitted || this._handleNavigationCommitted.bind(this)
        browser.webNavigation.onCommitted.addListener(this._onCommitted)
        this._listenerAttached = true
    }

    isActive() {
        return this.active && !!this.baseUrl
    }

    getBaseUrl() {
        return this.baseUrl
    }

    onZapDetected(cb) {
        if (typeof cb !== 'function') {
            return () => {}
        }

        this._detectedCallbacks.add(cb)
        return () => this._detectedCallbacks.delete(cb)
    }

    async postJson(obj) {
        if (!this.baseUrl) {
            throw new Error('zap_callback_not_ready')
        }

        let lastError = null
        for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
            try {
                const response = await fetch(this.baseUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(obj)
                })

                if (!response.ok) {
                    throw new Error(`zap_callback_http_${response.status}`)
                }

                return response
            } catch (err) {
                lastError = err
                if (attempt >= RETRY_DELAYS_MS.length) {
                    break
                }
                await sleep(RETRY_DELAYS_MS[attempt])
            }
        }

        throw lastError || new Error('zap_callback_failed')
    }

    _handleNavigationCommitted(details) {
        if (!details || details.frameId !== 0) return

        const url = details.url || ''
        if (!url.includes('zapenable=true')) return

        const match = url.match(DETECTION_REGEX)
        if (!match) return

        const secret = match[1]
        const baseUrl = `https://zap/zapCallBackUrl/${secret}/ptk`
        const changed = this.baseUrl !== baseUrl

        this.secret = secret
        this.baseUrl = baseUrl
        this.active = true

        this._emitDetected({
            secret,
            baseUrl,
            changed
        })
    }

    _emitDetected(payload) {
        for (const cb of this._detectedCallbacks) {
            try {
                cb(payload)
            } catch (err) {
                console.warn('[PTK ZAP] onZapDetected callback failed:', err)
            }
        }
    }
}

const zapTransport = new ZapTransport()

export default zapTransport
