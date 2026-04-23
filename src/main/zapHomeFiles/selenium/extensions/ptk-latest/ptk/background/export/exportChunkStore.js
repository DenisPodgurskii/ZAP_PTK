const DEFAULT_CHUNK_SIZE = 256 * 1024
const DEFAULT_TTL_MS = 5 * 60 * 1000
const DEFAULT_MAX_ENTRIES = 4

function makeRandomHex(size = 12) {
    try {
        const bytes = new Uint8Array(size)
        crypto.getRandomValues(bytes)
        return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
    } catch (_) {
        return Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2)
    }
}

function normalizeCompressedFilename(fileName, fallback = "PTK_scan.json") {
    const base = String(fileName || fallback || "PTK_scan.json").trim() || "PTK_scan.json"
    return /\.gz$/i.test(base) ? base : `${base}.gz`
}

function toBytes(bytes) {
    if (bytes instanceof Uint8Array) return bytes
    if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes)
    if (Array.isArray(bytes)) return Uint8Array.from(bytes)
    return new Uint8Array(0)
}

function toPositiveInteger(value, fallback) {
    const n = Number(value)
    if (!Number.isFinite(n) || n <= 0) return fallback
    return Math.floor(n)
}

export class ExportChunkStore {
    constructor(opts = {}) {
        this.prefix = String(opts.prefix || "scan")
        this.chunkSize = toPositiveInteger(opts.chunkSize, DEFAULT_CHUNK_SIZE)
        this.ttlMs = toPositiveInteger(opts.ttlMs, DEFAULT_TTL_MS)
        this.maxEntries = toPositiveInteger(opts.maxEntries, DEFAULT_MAX_ENTRIES)
        this.entries = new Map()
    }

    _cleanupExpired(now = Date.now()) {
        for (const [id, entry] of this.entries.entries()) {
            if (!entry || entry.expiresAt <= now) {
                this.entries.delete(id)
            }
        }
    }

    _enforceMaxEntries() {
        if (this.entries.size <= this.maxEntries) return
        const sorted = Array.from(this.entries.entries()).sort((a, b) => {
            const left = Number(a?.[1]?.createdAt || 0)
            const right = Number(b?.[1]?.createdAt || 0)
            return left - right
        })
        while (sorted.length && this.entries.size > this.maxEntries) {
            const oldest = sorted.shift()
            if (oldest?.[0]) this.entries.delete(oldest[0])
        }
    }

    createEntry({ bytes, fileName, contentType = "application/gzip", compression = "gzip" } = {}) {
        const payload = toBytes(bytes)
        if (!payload.length) return null
        const now = Date.now()
        this._cleanupExpired(now)
        const exportId = `${this.prefix}_${now}_${makeRandomHex(12)}`
        const chunkCount = Math.max(1, Math.ceil(payload.length / this.chunkSize))
        const entry = {
            exportId,
            createdAt: now,
            expiresAt: now + this.ttlMs,
            fileName: normalizeCompressedFilename(fileName),
            size: payload.length,
            chunkSize: this.chunkSize,
            chunkCount,
            contentType: contentType || "application/gzip",
            compression: compression || "gzip",
            bytes: payload
        }
        this.entries.set(exportId, entry)
        this._enforceMaxEntries()
        return {
            exportId,
            fileName: entry.fileName,
            size: entry.size,
            chunkSize: entry.chunkSize,
            chunkCount: entry.chunkCount,
            contentType: entry.contentType,
            compression: entry.compression,
            expiresAt: entry.expiresAt
        }
    }

    getChunk(exportId, index) {
        this._cleanupExpired()
        const id = String(exportId || "")
        if (!id) return null
        const entry = this.entries.get(id)
        if (!entry) return null
        const chunkIndex = Number(index)
        if (!Number.isInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= entry.chunkCount) {
            return null
        }
        const start = chunkIndex * entry.chunkSize
        const end = Math.min(entry.size, start + entry.chunkSize)
        return {
            exportId: id,
            index: chunkIndex,
            chunkCount: entry.chunkCount,
            chunk: entry.bytes.slice(start, end),
            fileName: entry.fileName,
            contentType: entry.contentType,
            compression: entry.compression
        }
    }

    release(exportId) {
        const id = String(exportId || "")
        if (!id) return false
        return this.entries.delete(id)
    }
}

export default ExportChunkStore
