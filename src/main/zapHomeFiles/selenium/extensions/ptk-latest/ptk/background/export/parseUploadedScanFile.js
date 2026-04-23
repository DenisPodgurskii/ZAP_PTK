import { parseDownloadedScanPayload } from "./parseDownloadedScanPayload.js"

const DEFAULT_UPLOAD_PARSE_LIMITS = {
    maxCompressedBytes: 150 * 1024 * 1024,
    maxDecompressedBytes: 180 * 1024 * 1024,
    maxCompressionRatio: 120
}

function headerLookup(headers) {
    const map = new Map()
    Object.entries(headers || {}).forEach(([key, value]) => {
        map.set(String(key || "").toLowerCase(), String(value || ""))
    })
    return {
        get(key) {
            return map.get(String(key || "").toLowerCase()) || ""
        }
    }
}

export async function parseUploadedScanFile(file, options = {}) {
    const filePayload = file && typeof file === "object" ? file : null
    const hasArrayBufferMethod = typeof filePayload?.arrayBuffer === "function"
    const serializedBuffer = filePayload?.buffer ?? filePayload?.bytes ?? null
    const hasSerializedBytes = serializedBuffer instanceof ArrayBuffer
        || ArrayBuffer.isView(serializedBuffer)
        || Array.isArray(serializedBuffer)
        || (!!serializedBuffer && typeof serializedBuffer === "object")

    if (!filePayload || (!hasArrayBufferMethod && !hasSerializedBytes)) {
        const err = new Error("Invalid file payload.")
        err.code = "invalid_file"
        throw err
    }

    const filename = String(filePayload?.name || "")
    const lowerName = filename.toLowerCase()
    const isGzipByName = lowerName.endsWith(".gz") || lowerName.endsWith(".gzip")
    const contentType = String(filePayload?.type || (isGzipByName ? "application/gzip" : "application/json"))

    const toArrayBuffer = async () => {
        if (hasArrayBufferMethod) {
            return filePayload.arrayBuffer()
        }
        if (serializedBuffer instanceof ArrayBuffer) {
            return serializedBuffer
        }
        if (ArrayBuffer.isView(serializedBuffer)) {
            const view = serializedBuffer
            return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength)
        }
        if (Array.isArray(serializedBuffer)) {
            return Uint8Array.from(serializedBuffer).buffer
        }
        if (serializedBuffer && typeof serializedBuffer === "object") {
            return Uint8Array.from(Object.values(serializedBuffer)).buffer
        }
        return new ArrayBuffer(0)
    }

    const responseLike = {
        async arrayBuffer() {
            return toArrayBuffer()
        },
        headers: headerLookup({
            "content-type": contentType,
            "content-disposition": filename ? `attachment; filename="${filename}"` : ""
        })
    }

    return parseDownloadedScanPayload(responseLike, {
        ...DEFAULT_UPLOAD_PARSE_LIMITS,
        ...(options || {})
    })
}

export default parseUploadedScanFile
