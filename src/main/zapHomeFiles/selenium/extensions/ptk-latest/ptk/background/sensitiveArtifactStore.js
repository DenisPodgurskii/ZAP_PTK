const DB_NAME = 'ptk_sensitive_artifacts_v1'
const DB_VERSION = 1
const STORE_NAME = 'artifacts'

const TTL_BY_KEY = Object.freeze({
    ptk_jwt: 24 * 60 * 60 * 1000,
    ptk_rbuilder: 7 * 24 * 60 * 60 * 1000,
    ptk_recorder: 30 * 24 * 60 * 60 * 1000,
    ptk_bugbounty_session_profiles_v1: 7 * 24 * 60 * 60 * 1000,
    ptk_bugbounty_evidence_packages_v1: 30 * 24 * 60 * 60 * 1000
})

function cloneValue(value) {
    if (typeof globalThis.structuredClone === 'function') {
        try {
            return globalThis.structuredClone(value)
        } catch (_) {
            // Fall through to the JSON-safe data model used by these stores.
        }
    }
    return JSON.parse(JSON.stringify(value ?? null))
}

function hasStoredValue(value) {
    if (Array.isArray(value)) return value.length > 0
    return !!value && typeof value === 'object' && Object.keys(value).length > 0
}

function requestResult(request) {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error || new Error('sensitive_store_request_failed'))
    })
}

export class SensitiveArtifactStore {
    constructor({
        indexedDBApi = globalThis.indexedDB,
        legacyStorage = globalThis.browser?.storage?.local,
        now = () => Date.now()
    } = {}) {
        this.indexedDBApi = indexedDBApi
        this.legacyStorage = legacyStorage
        this.now = now
        this.memory = new Map()
        this.dbPromise = null
    }

    async _open() {
        if (!this.indexedDBApi?.open) return null
        if (!this.dbPromise) {
            this.dbPromise = new Promise((resolve, reject) => {
                const request = this.indexedDBApi.open(DB_NAME, DB_VERSION)
                request.onupgradeneeded = () => {
                    const db = request.result
                    if (!db.objectStoreNames.contains(STORE_NAME)) {
                        db.createObjectStore(STORE_NAME, { keyPath: 'key' })
                    }
                }
                request.onsuccess = () => resolve(request.result)
                request.onerror = () => reject(request.error || new Error('sensitive_store_open_failed'))
            }).catch(() => null)
        }
        return this.dbPromise
    }

    _record(key, value, ttlMs = TTL_BY_KEY[key]) {
        const createdAt = this.now()
        return {
            key,
            value: cloneValue(value),
            createdAt,
            lastAccessedAt: createdAt,
            expiresAt: Number.isFinite(ttlMs) && ttlMs > 0 ? createdAt + ttlMs : null
        }
    }

    async _readRecord(key) {
        const db = await this._open()
        if (!db) return this.memory.get(key) || null
        const transaction = db.transaction(STORE_NAME, 'readonly')
        return requestResult(transaction.objectStore(STORE_NAME).get(key))
    }

    async _writeRecord(record) {
        const db = await this._open()
        if (!db) {
            this.memory.set(record.key, cloneValue(record))
            return
        }
        const transaction = db.transaction(STORE_NAME, 'readwrite')
        await requestResult(transaction.objectStore(STORE_NAME).put(record))
    }

    async _removeRecord(key) {
        this.memory.delete(key)
        const db = await this._open()
        if (!db) return
        const transaction = db.transaction(STORE_NAME, 'readwrite')
        await requestResult(transaction.objectStore(STORE_NAME).delete(key))
    }

    async _migrateLegacy(key) {
        if (!this.legacyStorage?.get) return null
        try {
            const stored = await this.legacyStorage.get(key)
            const value = stored?.[key]
            if (!hasStoredValue(value)) return null
            await this.setItem(key, value)
            await this.legacyStorage.remove?.(key)
            return cloneValue(value)
        } catch (_) {
            return null
        }
    }

    async getItem(key) {
        let record = await this._readRecord(key)
        if (!record) {
            const migrated = await this._migrateLegacy(key)
            return migrated ?? {}
        }
        if (record.expiresAt && record.expiresAt <= this.now()) {
            await this._removeRecord(key)
            return {}
        }
        record.lastAccessedAt = this.now()
        await this._writeRecord(record)
        return hasStoredValue(record.value) ? cloneValue(record.value) : {}
    }

    async setItem(key, value, { ttlMs = TTL_BY_KEY[key] } = {}) {
        await this._writeRecord(this._record(key, value, ttlMs))
    }

    async removeItem(key) {
        await this._removeRecord(key)
        try {
            await this.legacyStorage?.remove?.(key)
        } catch (_) {
            // The background-only copy has already been removed.
        }
    }

    async clearExpired() {
        const db = await this._open()
        if (!db) {
            for (const [key, record] of this.memory.entries()) {
                if (record.expiresAt && record.expiresAt <= this.now()) this.memory.delete(key)
            }
            return
        }
        const transaction = db.transaction(STORE_NAME, 'readonly')
        const store = transaction.objectStore(STORE_NAME)
        const records = await requestResult(store.getAll())
        await Promise.all(records
            .filter((record) => record.expiresAt && record.expiresAt <= this.now())
            .map((record) => this._removeRecord(record.key)))
    }

    async clearAll() {
        this.memory.clear()
        const db = await this._open()
        if (!db) return
        const transaction = db.transaction(STORE_NAME, 'readwrite')
        await requestResult(transaction.objectStore(STORE_NAME).clear())
    }
}

export const sensitiveArtifactStorage = new SensitiveArtifactStore()
export const sensitiveArtifactTtls = TTL_BY_KEY
