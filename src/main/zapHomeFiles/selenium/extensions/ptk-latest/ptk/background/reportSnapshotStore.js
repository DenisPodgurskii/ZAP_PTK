const REPORT_SNAPSHOT_KEY_PREFIX = 'ptk_report_snapshot_v1:'
const REPORT_SNAPSHOT_TTL_MS = 5 * 60 * 1000
const REPORT_SNAPSHOT_ID_PATTERN = /^(?:[a-f0-9]{48}|[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/

function createReportSnapshotId(cryptoApi = globalThis.crypto) {
    if (typeof cryptoApi?.randomUUID === 'function') {
        return cryptoApi.randomUUID()
    }
    if (typeof cryptoApi?.getRandomValues !== 'function') {
        throw new Error('secure_random_unavailable')
    }
    const bytes = new Uint8Array(24)
    cryptoApi.getRandomValues(bytes)
    return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
}

function reportSnapshotStorageKey(snapshotId) {
    const normalized = String(snapshotId || '').trim().toLowerCase()
    if (!REPORT_SNAPSHOT_ID_PATTERN.test(normalized)) return null
    return `${REPORT_SNAPSHOT_KEY_PREFIX}${normalized}`
}

export class ReportSnapshotStore {
    constructor({ storage, cryptoApi = globalThis.crypto, ttlMs = REPORT_SNAPSHOT_TTL_MS } = {}) {
        this.storage = storage
        this.cryptoApi = cryptoApi
        this.ttlMs = ttlMs
    }

    async create(snapshot) {
        if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
            return { success: false, error: 'invalid_report_snapshot' }
        }
        if (!this.storage?.setItem) {
            return { success: false, error: 'report_snapshot_store_unavailable' }
        }
        try {
            const snapshotId = createReportSnapshotId(this.cryptoApi)
            const key = reportSnapshotStorageKey(snapshotId)
            await this.storage.setItem(key, snapshot, { ttlMs: this.ttlMs })
            return { success: true, snapshotId }
        } catch (error) {
            return { success: false, error: error?.message || 'report_snapshot_store_failed' }
        }
    }

    async consume(snapshotId) {
        const key = reportSnapshotStorageKey(snapshotId)
        if (!key) return { success: false, error: 'invalid_report_snapshot_id' }
        if (!this.storage?.getItem || !this.storage?.removeItem) {
            return { success: false, error: 'report_snapshot_store_unavailable' }
        }
        try {
            const snapshot = await this.storage.getItem(key)
            await this.storage.removeItem(key)
            if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot) || !Object.keys(snapshot).length) {
                return { success: false, error: 'report_snapshot_not_found' }
            }
            return { success: true, snapshot }
        } catch (error) {
            await this.storage.removeItem(key).catch(() => { })
            return { success: false, error: error?.message || 'report_snapshot_read_failed' }
        }
    }
}

export {
    createReportSnapshotId,
    reportSnapshotStorageKey,
    REPORT_SNAPSHOT_KEY_PREFIX,
    REPORT_SNAPSHOT_TTL_MS
}

