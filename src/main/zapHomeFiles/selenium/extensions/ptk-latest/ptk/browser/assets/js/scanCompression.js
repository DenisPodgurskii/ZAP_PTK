function ensureCompressionSupport(apiName) {
    if (apiName === "compress" && typeof CompressionStream !== "function") {
        throw new Error("Gzip compression is not supported in this browser.")
    }
    if (apiName === "decompress" && typeof DecompressionStream !== "function") {
        throw new Error("Gzip decompression is not supported in this browser.")
    }
}

function isGzipBytes(bytes) {
    return bytes && bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b
}

async function gzipText(text) {
    ensureCompressionSupport("compress")
    const bytes = new TextEncoder().encode(text)
    const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"))
    const compressed = await new Response(stream).arrayBuffer()
    return new Uint8Array(compressed)
}

async function gunzipToText(bytes) {
    ensureCompressionSupport("decompress")
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"))
    return await new Response(stream).text()
}

function normalizeCompressedFilename(fileName) {
    const name = String(fileName || "PTK_scan.json")
    return name.endsWith(".gz") ? name : `${name}.gz`
}

function triggerDownloadBlob(blob, fileName) {
    const downloadLink = document.createElement("a")
    downloadLink.download = normalizeCompressedFilename(fileName)
    downloadLink.innerHTML = "Download File"
    downloadLink.href = window.URL.createObjectURL(blob)
    downloadLink.click()
}

function toUint8Array(chunk) {
    if (!chunk) return new Uint8Array(0)
    if (chunk instanceof Uint8Array) return chunk
    if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk)
    if (Array.isArray(chunk)) return Uint8Array.from(chunk)
    if (typeof chunk === "object") return Uint8Array.from(Object.values(chunk))
    return new Uint8Array(0)
}

export async function createCompressedScanDownload(scanResult, fileName) {
    const json = JSON.stringify(scanResult)
    const compressed = await gzipText(json)
    return {
        fileName: normalizeCompressedFilename(fileName),
        blob: new Blob([compressed], { type: "application/gzip" })
    }
}

export async function downloadChunkedScanExport(controller, descriptor, fallbackFileName, options = {}) {
    if (!descriptor || descriptor.exportMode !== "chunked") return false
    const onProgress = typeof options?.onProgress === "function" ? options.onProgress : null
    const exportId = descriptor.exportId
    const chunkCount = Number(descriptor.chunkCount || 0)
    if (!exportId || !Number.isInteger(chunkCount) || chunkCount <= 0) {
        throw new Error("Invalid export descriptor.")
    }

    const chunks = []
    try {
        if (onProgress) {
            onProgress({
                phase: "chunk_start",
                completed: 0,
                total: chunkCount
            })
        }
        for (let i = 0; i < chunkCount; i++) {
            const res = await controller.getExportScanChunk(exportId, i)
            if (!res || res.success === false) {
                throw new Error(res?.error || "Failed to read export chunk.")
            }
            const bytes = toUint8Array(res.chunk)
            if (!bytes.length) {
                throw new Error("Export chunk is empty.")
            }
            chunks.push(bytes)
            if (onProgress) {
                onProgress({
                    phase: "chunk_download",
                    completed: i + 1,
                    total: chunkCount
                })
            }
        }
    } finally {
        try {
            await controller.releaseExportScan(exportId)
        } catch (_) { }
    }

    const blob = new Blob(chunks, { type: descriptor.contentType || "application/gzip" })
    triggerDownloadBlob(blob, descriptor.fileName || fallbackFileName || "PTK_scan.json")
    if (onProgress) {
        onProgress({
            phase: "done",
            completed: chunkCount,
            total: chunkCount
        })
    }
    return true
}

export async function downloadScanExportResult(controller, exportResult, fallbackFileName, options = {}) {
    if (!exportResult) return false
    const onProgress = typeof options?.onProgress === "function" ? options.onProgress : null
    if (exportResult.exportMode === "chunked") {
        return downloadChunkedScanExport(controller, exportResult, fallbackFileName, options)
    }
    if (onProgress) {
        onProgress({
            phase: "chunk_start",
            completed: 0,
            total: 1
        })
    }
    const download = await createCompressedScanDownload(exportResult, fallbackFileName)
    triggerDownloadBlob(download.blob, download.fileName)
    if (onProgress) {
        onProgress({
            phase: "done",
            completed: 1,
            total: 1
        })
    }
    return true
}

export async function readScanFileText(file) {
    if (!file) throw new Error("No file selected.")
    const bytes = new Uint8Array(await file.arrayBuffer())
    const isGzip = isGzipBytes(bytes) || /\.gz$/i.test(String(file.name || ""))
    if (!isGzip) {
        return new TextDecoder().decode(bytes)
    }
    return gunzipToText(bytes)
}
