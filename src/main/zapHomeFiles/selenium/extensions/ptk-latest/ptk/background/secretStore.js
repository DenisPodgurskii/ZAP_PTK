import { ptk_utils } from './utils.js'
import { PORTAL_BASE_URL } from '../common/portalConfig.js'

const DB_NAME = 'ptk_background_secrets_v1'
const DB_VERSION = 1
const STORE_NAME = 'secrets'
const PORTAL_TOKEN_KEY = 'portal_pat'
const MAX_SECRET_LENGTH = 16 * 1024
const MAX_RESPONSE_LENGTH = 64 * 1024
const REQUEST_TIMEOUT_MS = 15000

function normalizeSecret(value) {
    const secret = typeof value === 'string' ? value.trim() : ''
    if (!secret || secret.length > MAX_SECRET_LENGTH) return ''
    return secret
}

function portalEndpoint(path) {
    return new URL(`/api/v1${path}`, `${PORTAL_BASE_URL}/`).toString()
}

function isProductionPortalResponse(response) {
    if (!response?.url) return true
    try {
        return new URL(response.url).origin === PORTAL_BASE_URL
    } catch (_) {
        return false
    }
}

async function fetchWithTimeout(fetchImpl, url, options = {}) {
    if (typeof AbortController === 'undefined') return fetchImpl(url, options)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
    try {
        return await fetchImpl(url, { ...options, signal: controller.signal })
    } finally {
        clearTimeout(timer)
    }
}

async function readBoundedJson(response) {
    const text = typeof response?.text === 'function' ? await response.text() : ''
    if (text.length > MAX_RESPONSE_LENGTH) throw new Error('portal_response_too_large')
    if (!text) return {}
    try {
        return JSON.parse(text)
    } catch (_) {
        return { message: text.slice(0, 512) }
    }
}

export class SecretStore {
    constructor({ indexedDBImpl = globalThis.indexedDB, fetchImpl = (...args) => fetch(...args) } = {}) {
        this.indexedDB = indexedDBImpl || null
        this.fetchImpl = fetchImpl
        this.dbPromise = null
        this.token = ''
        this.valid = null
        this.lastValidatedAt = null
        this.initialized = false
        this.initializationPromise = null
        this.memoryFallback = new Map()
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    _openDb() {
        if (!this.indexedDB) return Promise.resolve(null)
        if (this.dbPromise) return this.dbPromise
        this.dbPromise = new Promise((resolve, reject) => {
            const request = this.indexedDB.open(DB_NAME, DB_VERSION)
            request.onupgradeneeded = () => {
                const db = request.result
                if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME)
            }
            request.onsuccess = () => resolve(request.result)
            request.onerror = () => reject(request.error || new Error('secret_store_open_failed'))
        })
        return this.dbPromise
    }

    async _read(key) {
        const db = await this._openDb()
        if (!db) return this.memoryFallback.get(key) || ''
        return new Promise((resolve, reject) => {
            const request = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(key)
            request.onsuccess = () => resolve(request.result || '')
            request.onerror = () => reject(request.error || new Error('secret_store_read_failed'))
        })
    }

    async _write(key, value) {
        const db = await this._openDb()
        if (!db) {
            this.memoryFallback.set(key, value)
            return true
        }
        return new Promise((resolve, reject) => {
            const request = db.transaction(STORE_NAME, 'readwrite').objectStore(STORE_NAME).put(value, key)
            request.onsuccess = () => resolve(true)
            request.onerror = () => reject(request.error || new Error('secret_store_write_failed'))
        })
    }

    async _delete(key) {
        const db = await this._openDb()
        if (!db) {
            this.memoryFallback.delete(key)
            return true
        }
        return new Promise((resolve, reject) => {
            const request = db.transaction(STORE_NAME, 'readwrite').objectStore(STORE_NAME).delete(key)
            request.onsuccess = () => resolve(true)
            request.onerror = () => reject(request.error || new Error('secret_store_delete_failed'))
        })
    }

    initialize({ legacyToken = '' } = {}) {
        if (this.initializationPromise) return this.initializationPromise
        this.initializationPromise = (async () => {
            let storedToken = ''
            try {
                storedToken = normalizeSecret(await this._read(PORTAL_TOKEN_KEY))
            } catch (_) {
                // Keep the extension usable if IndexedDB is unavailable, while
                // retaining the secret only in this background context.
                this.indexedDB = null
                this.dbPromise = null
                storedToken = normalizeSecret(this.memoryFallback.get(PORTAL_TOKEN_KEY))
            }
            const migrationToken = normalizeSecret(legacyToken)
            this.token = storedToken || migrationToken
            if (!storedToken && migrationToken) {
                try {
                    await this._write(PORTAL_TOKEN_KEY, migrationToken)
                } catch (_) {
                    this.memoryFallback.set(PORTAL_TOKEN_KEY, migrationToken)
                }
            }
            this.initialized = true
            return this.getStatus()
        })()
        return this.initializationPromise
    }

    async ready() {
        if (!this.initializationPromise) await this.initialize()
        else await this.initializationPromise
    }

    getTokenSync() {
        return this.token
    }

    getStatus() {
        const configured = !!this.token
        return {
            configured,
            valid: configured ? this.valid : false,
            fingerprint: configured ? `••••${this.token.slice(-4)}` : null,
            lastValidatedAt: this.lastValidatedAt
        }
    }

    async setToken(token) {
        const normalized = normalizeSecret(token)
        if (!normalized) throw new Error('invalid_portal_token')
        await this._write(PORTAL_TOKEN_KEY, normalized)
        this.token = normalized
        this.valid = null
        this.lastValidatedAt = null
        return this.getStatus()
    }

    async clear() {
        await this._delete(PORTAL_TOKEN_KEY)
        this.token = ''
        this.valid = false
        this.lastValidatedAt = null
        return this.getStatus()
    }

    async validate() {
        await this.ready()
        if (!this.token) return { success: false, status: this.getStatus(), message: 'No API key found' }
        const response = await fetchWithTimeout(this.fetchImpl, portalEndpoint('/tokens/validate'), {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${this.token}`,
                Accept: 'application/json'
            },
            credentials: 'omit',
            redirect: 'error',
            cache: 'no-store'
        })
        if (!isProductionPortalResponse(response)) throw new Error('untrusted_portal_response_origin')
        const payload = await readBoundedJson(response)
        this.valid = response.ok === true
        this.lastValidatedAt = new Date().toISOString()
        return {
            success: this.valid,
            status: this.getStatus(),
            message: this.valid
                ? 'API token validated successfully.'
                : (payload?.message || payload?.error || 'Token validation failed.')
        }
    }

    async activate(activationToken) {
        await this.ready()
        const normalizedActivationToken = normalizeSecret(activationToken)
        if (!normalizedActivationToken) {
            return { success: false, status: this.getStatus(), message: 'Activation token is required.' }
        }
        const response = await fetchWithTimeout(this.fetchImpl, portalEndpoint('/tokens/activate'), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            credentials: 'omit',
            redirect: 'error',
            cache: 'no-store',
            body: JSON.stringify({
                activation_token: normalizedActivationToken,
                ptk_agent: 'ptk-browser-extension'
            })
        })
        if (!isProductionPortalResponse(response)) throw new Error('untrusted_portal_response_origin')
        const payload = await readBoundedJson(response)
        const issuedToken = normalizeSecret(payload?.token)
        if (!response.ok || !issuedToken) {
            return {
                success: false,
                status: this.getStatus(),
                message: payload?.message || payload?.error || 'Unable to activate token.'
            }
        }
        await this.setToken(issuedToken)
        try {
            return await this.validate()
        } catch (_) {
            return {
                success: true,
                status: this.getStatus(),
                message: 'API token activated successfully.'
            }
        }
    }

    onMessage(message, sender) {
        if (message?.channel !== 'ptk_popup2background_secrets') return undefined
        return this._handleMessage(message, sender)
    }

    async _handleMessage(message, sender) {
        if (!ptk_utils.isTrustedExtensionPageSender(sender)) {
            return { success: false, error: 'untrusted_extension_sender' }
        }
        await this.ready()
        try {
            if (message.type === 'get_status') return { success: true, status: this.getStatus() }
            if (message.type === 'activate') return this.activate(message.activationToken)
            if (message.type === 'validate') return this.validate()
            if (message.type === 'clear') return { success: true, status: await this.clear() }
            return { success: false, error: 'unsupported_secret_operation' }
        } catch (err) {
            return {
                success: false,
                error: err?.name === 'AbortError' ? 'portal_request_timeout' : 'portal_secret_operation_failed',
                message: err?.name === 'AbortError' ? 'Portal request timed out.' : 'Unable to complete the portal request.',
                status: this.getStatus()
            }
        }
    }
}

export const __secretStoreTestHooks = Object.freeze({
    normalizeSecret,
    portalEndpoint,
    isProductionPortalResponse
})
