const PREFIX = 'ptk_proxy_history_v1:'
const META_PREFIX = `${PREFIX}meta:`
const ENTRY_PREFIX = `${PREFIX}request:`

function bytesToBase64(bytes) {
    let binary = ''
    for (let index = 0; index < bytes.length; index += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000))
    }
    return btoa(binary)
}

function base64ToBytes(value) {
    const binary = atob(value)
    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
    return bytes
}

function encodeRecord(record) {
    return JSON.parse(JSON.stringify(record, (_key, value) => {
        if (value instanceof ArrayBuffer) {
            return { __ptkProxyArrayBufferV1: bytesToBase64(new Uint8Array(value)) }
        }
        if (ArrayBuffer.isView(value)) {
            return { __ptkProxyArrayBufferV1: bytesToBase64(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)) }
        }
        return value
    }))
}

function decodeRecord(record) {
    return JSON.parse(JSON.stringify(record), (_key, value) => {
        if (value && typeof value === 'object' && typeof value.__ptkProxyArrayBufferV1 === 'string') {
            return base64ToBytes(value.__ptkProxyArrayBufferV1).buffer
        }
        return value
    })
}

function recordBytes(key, value) {
    return new TextEncoder().encode(key + JSON.stringify(value)).length
}

function requestKey(tabId, frameId, requestId) {
    return `${ENTRY_PREFIX}${tabId}:${frameId}:${encodeURIComponent(String(requestId))}`
}

function metaKey(tabId) {
    return `${META_PREFIX}${tabId}`
}

export class ProxySessionHistory {
    constructor({
        captureStore,
        storageArea = globalThis.browser?.storage?.session,
        tabsApi = globalThis.browser?.tabs,
        maxRequestsPerTab = 1000,
        maxBytesPerTab = 2 * 1024 * 1024,
        maxBytesTotal = 8 * 1024 * 1024,
        batchMs = 250,
        onError = () => {}
    } = {}) {
        this.captureStore = captureStore
        this.storageArea = storageArea
        this.tabsApi = tabsApi
        this.maxRequestsPerTab = maxRequestsPerTab
        this.maxBytesPerTab = maxBytesPerTab
        this.maxBytesTotal = maxBytesTotal
        this.batchMs = batchMs
        this.onError = onError
        this.activeScanTabId = null
        this.entries = new Map()
        this.pending = new Map()
        this.timers = new Map()
        this.truncatedTabs = new Set()
        this.recoveredTabs = new Set()
        this.failedTabs = new Set()
        this.closedTabs = new Set()
        this._writeChain = Promise.resolve()
        this.ready = this._restore().catch(error => this._reportError(error, null))
    }

    _reportError(error, tabId) {
        if (tabId != null) this.failedTabs.add(tabId)
        try {
            this.onError({ code: 'proxy_session_history_unavailable', tabId, reason: error?.name || 'storage_error' })
        } catch (_) { }
    }

    _status(tabId) {
        return {
            historyRecovered: this.recoveredTabs.has(tabId),
            historyTruncated: this.truncatedTabs.has(tabId),
            historyPersistenceError: this.failedTabs.has(tabId)
        }
    }

    status(tabId) {
        return this._status(tabId)
    }

    async _restore() {
        if (!this.storageArea?.get || !this.tabsApi?.query) return
        const [stored, openTabs] = await Promise.all([
            this.storageArea.get(null),
            this.tabsApi.query({})
        ])
        const openIds = new Set((openTabs || []).map(tab => tab?.id).filter(Number.isInteger))
        const staleKeys = []
        const records = []
        for (const [key, value] of Object.entries(stored || {})) {
            if (!key.startsWith(PREFIX)) continue
            const tabId = Number(value?.tabId ?? (key.startsWith(META_PREFIX) ? key.slice(META_PREFIX.length) : NaN))
            if (!Number.isInteger(tabId) || !openIds.has(tabId) || this.closedTabs.has(tabId)) {
                staleKeys.push(key)
                continue
            }
            if (key.startsWith(META_PREFIX)) {
                if (value?.truncated === true) this.truncatedTabs.add(tabId)
                continue
            }
            if (!key.startsWith(ENTRY_PREFIX) || value?.schema !== 1
                || !Number.isInteger(value.frameId) || !Array.isArray(value.events)
                || !value.events.length || typeof value.requestId !== 'string') {
                staleKeys.push(key)
                continue
            }
            records.push({ key, value })
        }
        records.sort((left, right) => Number(left.value.updatedAt || 0) - Number(right.value.updatedAt || 0))
        for (const { key, value } of records) {
            try {
                if (this.closedTabs.has(value.tabId)) {
                    staleKeys.push(key)
                    continue
                }
                const decoded = decodeRecord(value)
                const restored = this.captureStore?.restoreRequestEvents?.(
                    decoded.tabId, decoded.frameId, decoded.requestId, decoded.events, decoded.uiUrl
                )
                if (restored) this.recoveredTabs.add(decoded.tabId)
                this.entries.set(key, {
                    tabId: decoded.tabId,
                    bytes: recordBytes(key, value),
                    updatedAt: Number(value.updatedAt || 0)
                })
            } catch (_) {
                staleKeys.push(key)
            }
        }
        if (staleKeys.length) await this.storageArea.remove(staleKeys)
    }

    beginScan(tabId) {
        if (!Number.isInteger(tabId) || tabId < 0) return
        if (this.activeScanTabId === tabId) return
        this.closedTabs.delete(tabId)
        this.activeScanTabId = tabId
        if (this.captureStore) this.captureStore.pinnedTabId = tabId
        if (!this.storageArea?.get || !this.storageArea?.set || !this.storageArea?.remove) {
            this._reportError({ name: 'session_storage_unavailable' }, tabId)
            return
        }
        void this.ready.then(() => {
            if (this.activeScanTabId !== tabId) return
            const tab = this.captureStore?.getTab(tabId)
            tab?.frames?.forEach((frame, frameId) => frame.forEach((events, requestId) => {
                if (events?.some(event => event?.__ptkEventType === 'response')) {
                    this.recordCompleted(tabId, frameId, requestId)
                }
            }))
        }).catch(error => this._reportError(error, tabId))
    }

    endScan(tabId = this.activeScanTabId) {
        if (tabId !== this.activeScanTabId) return
        this.activeScanTabId = null
        if (this.captureStore) this.captureStore.pinnedTabId = null
        void this.flush(tabId)
    }

    recordCompleted(tabId, frameId, requestId) {
        if (tabId !== this.activeScanTabId || !this.storageArea?.set) return
        if (!Number.isInteger(frameId) || requestId == null) return
        const pending = this.pending.get(tabId) || new Map()
        pending.set(requestKey(tabId, frameId, requestId), { frameId, requestId: String(requestId) })
        this.pending.set(tabId, pending)
        if (this.timers.has(tabId)) return
        this.timers.set(tabId, setTimeout(() => {
            this.timers.delete(tabId)
            void this.flush(tabId)
        }, this.batchMs))
    }

    _oldestKey(entries, tabId = null) {
        let oldest = null
        for (const [key, entry] of entries) {
            if (tabId != null && entry.tabId !== tabId) continue
            if (!oldest || entry.updatedAt < oldest.entry.updatedAt) oldest = { key, entry }
        }
        return oldest?.key || null
    }

    _totalBytes(entries, tabId = null) {
        let total = 0
        for (const entry of entries.values()) {
            if (tabId == null || entry.tabId === tabId) total += entry.bytes
        }
        return total
    }

    _tabCount(entries, tabId) {
        let count = 0
        for (const entry of entries.values()) if (entry.tabId === tabId) count += 1
        return count
    }

    async flush(tabId) {
        const timer = this.timers.get(tabId)
        if (timer) clearTimeout(timer)
        this.timers.delete(tabId)
        const pending = this.pending.get(tabId)
        this.pending.delete(tabId)
        if (!pending?.size || !this.storageArea?.set) return this._writeChain
        this._writeChain = this._writeChain.then(async () => {
            await this.ready
            const nextEntries = new Map(this.entries)
            const writes = {}
            const removals = new Set()
            const newlyTruncated = new Set()
            for (const [key, identity] of pending) {
                const events = this.captureStore?.getTab(tabId)?.frames?.get(identity.frameId)?.get(identity.requestId)
                if (!Array.isArray(events) || !events.length) continue
                let record
                try {
                    record = encodeRecord({
                        schema: 1, tabId, frameId: identity.frameId, requestId: identity.requestId,
                        uiUrl: this.captureStore.getUiUrl(tabId, events[0]?.ui_url || events[0]?.url || ''),
                        updatedAt: Date.now(), events
                    })
                } catch (_) {
                    newlyTruncated.add(tabId)
                    continue
                }
                const bytes = recordBytes(key, record)
                if (bytes > this.maxBytesPerTab || bytes > this.maxBytesTotal) {
                    newlyTruncated.add(tabId)
                    continue
                }
                writes[key] = record
                nextEntries.delete(key)
                nextEntries.set(key, { tabId, bytes, updatedAt: record.updatedAt })
            }
            while (this._tabCount(nextEntries, tabId) > this.maxRequestsPerTab
                || this._totalBytes(nextEntries, tabId) > this.maxBytesPerTab) {
                const oldest = this._oldestKey(nextEntries, tabId)
                if (!oldest) break
                nextEntries.delete(oldest)
                delete writes[oldest]
                removals.add(oldest)
                newlyTruncated.add(tabId)
            }
            while (this._totalBytes(nextEntries) > this.maxBytesTotal) {
                const oldest = this._oldestKey(nextEntries)
                if (!oldest) break
                const owner = nextEntries.get(oldest)?.tabId
                nextEntries.delete(oldest)
                delete writes[oldest]
                removals.add(oldest)
                if (owner != null) newlyTruncated.add(owner)
            }
            for (const owner of newlyTruncated) {
                writes[metaKey(owner)] = { tabId: owner, truncated: true }
            }
            if (removals.size) await this.storageArea.remove([...removals])
            if (Object.keys(writes).length) await this.storageArea.set(writes)
            this.entries = nextEntries
            for (const owner of newlyTruncated) this.truncatedTabs.add(owner)
            this.failedTabs.delete(tabId)
        }).catch(error => this._reportError(error, tabId))
        return this._writeChain
    }

    async removeTab(tabId) {
        this.closedTabs.add(tabId)
        const hadHistory = this.activeScanTabId === tabId
            || this.pending.has(tabId)
            || this.truncatedTabs.has(tabId)
            || [...this.entries.values()].some(entry => entry.tabId === tabId)
        const timer = this.timers.get(tabId)
        if (timer) clearTimeout(timer)
        this.timers.delete(tabId)
        this.pending.delete(tabId)
        if (this.activeScanTabId === tabId) this.endScan(tabId)
        this.recoveredTabs.delete(tabId)
        this.truncatedTabs.delete(tabId)
        this.failedTabs.delete(tabId)
        if (!hadHistory) return this._writeChain
        this._writeChain = this._writeChain.then(async () => {
            await this.ready
            const keys = [...this.entries].filter(([_key, entry]) => entry.tabId === tabId).map(([key]) => key)
            keys.push(metaKey(tabId))
            if (this.storageArea?.remove) await this.storageArea.remove(keys)
            for (const key of keys) this.entries.delete(key)
        }).catch(error => this._reportError(error, tabId))
        return this._writeChain
    }
}
