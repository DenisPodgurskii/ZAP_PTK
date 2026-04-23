const DEFAULT_LIMITS = {
    maxCompressedBytes: 20 * 1024 * 1024,
    maxDecompressedBytes: 30 * 1024 * 1024,
    maxCompressionRatio: 120
}

function buildDecodeError(code, message) {
    const err = new Error(message)
    err.code = code
    return err
}

function isGzipBytes(bytes) {
    return !!(bytes && bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b)
}

function headerValue(response, key) {
    try {
        return String(response?.headers?.get?.(key) || "")
    } catch (_) {
        return ""
    }
}

function wantsGzipByHeaders(response) {
    const contentType = headerValue(response, "content-type").toLowerCase()
    const contentEncoding = headerValue(response, "content-encoding").toLowerCase()
    const contentDisposition = headerValue(response, "content-disposition").toLowerCase()
    const xCompression = headerValue(response, "x-ptk-compression").toLowerCase()

    if (contentEncoding.includes("gzip")) return true
    if (xCompression.includes("gzip")) return true
    if (contentType.includes("application/gzip") || contentType.includes("application/x-gzip")) return true
    if (contentDisposition.includes(".gz")) return true
    return false
}

async function gunzipBytes(bytes) {
    if (typeof DecompressionStream !== "function") {
        throw buildDecodeError(
            "gzip_not_supported",
            "Gzip decompression is not supported in this browser runtime."
        )
    }
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"))
    const inflated = await new Response(stream).arrayBuffer()
    return new Uint8Array(inflated)
}

function decodeUtf8(bytes) {
    try {
        return new TextDecoder("utf-8", { fatal: false }).decode(bytes)
    } catch (_) {
        return ""
    }
}

function safeJsonParse(text) {
    try {
        return { ok: true, json: JSON.parse(text) }
    } catch (err) {
        return { ok: false, error: err }
    }
}

export async function parseDownloadedScanPayload(response, options = {}) {
    if (!response || typeof response.arrayBuffer !== "function") {
        throw buildDecodeError("invalid_response", "Invalid download response.")
    }

    const limits = Object.assign({}, DEFAULT_LIMITS, options || {})
    const rawBuffer = await response.arrayBuffer()
    const rawBytes = new Uint8Array(rawBuffer)
    if (rawBytes.length > limits.maxCompressedBytes) {
        throw buildDecodeError("payload_too_large", "Downloaded payload exceeds size limits.")
    }

    const shouldGunzip = wantsGzipByHeaders(response) || isGzipBytes(rawBytes)
    let decodedBytes = rawBytes

    if (shouldGunzip) {
        decodedBytes = await gunzipBytes(rawBytes)
        if (decodedBytes.length > limits.maxDecompressedBytes) {
            throw buildDecodeError("payload_too_large", "Decompressed payload exceeds size limits.")
        }
        const ratio = decodedBytes.length / Math.max(1, rawBytes.length)
        if (Number.isFinite(ratio) && ratio > limits.maxCompressionRatio) {
            throw buildDecodeError(
                "compression_ratio_exceeded",
                "Compressed payload expansion ratio exceeds limits."
            )
        }
    } else if (decodedBytes.length > limits.maxDecompressedBytes) {
        throw buildDecodeError("payload_too_large", "Downloaded payload exceeds size limits.")
    }

    const text = decodeUtf8(decodedBytes)
    const parsed = safeJsonParse(text)
    return {
        ok: parsed.ok,
        json: parsed.ok ? parsed.json : null,
        text,
        isGzip: shouldGunzip,
        parseError: parsed.ok ? null : parsed.error
    }
}

export default parseDownloadedScanPayload
