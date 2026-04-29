import { compressScanPayload } from "../../export/compressScanPayload.js"
import { ExportChunkStore } from "../../export/exportChunkStore.js"

export class DastExportService {
    constructor({
        lifecycleService = null,
        chunkStore = new ExportChunkStore({ prefix: "dast" }),
        compressPayload = compressScanPayload
    } = {}) {
        this.lifecycleService = lifecycleService
        this.chunkStore = chunkStore
        this.compressPayload = compressPayload
    }

    async createChunkedExport(scanResult, { target = "download", fileName = "PTK_DAST_scan.json", includeSecrets = false } = {}) {
        if (!scanResult || typeof scanResult !== "object") return null
        const payload = this.lifecycleService?.buildExportPayload?.(scanResult, {
            target,
            includeSecrets: includeSecrets === true
        })
        if (!payload) return null
        const compressed = await this.compressPayload(payload)
        const descriptor = this.chunkStore.createEntry({
            bytes: compressed.body,
            fileName,
            contentType: compressed.contentType,
            compression: compressed.compression
        })
        if (!descriptor) {
            return { success: false, error: "empty_export_payload" }
        }
        return {
            success: true,
            exportMode: "chunked",
            ...descriptor
        }
    }

    getChunk(exportId, index) {
        const chunk = this.chunkStore.getChunk(exportId, index)
        if (!chunk) {
            return { success: false, error: "export_not_found_or_expired" }
        }
        return {
            success: true,
            exportMode: "chunked",
            exportId: chunk.exportId,
            index: chunk.index,
            chunkCount: chunk.chunkCount,
            chunk: chunk.chunk
        }
    }

    release(exportId) {
        return { success: this.chunkStore.release(exportId) }
    }
}

export default DastExportService
