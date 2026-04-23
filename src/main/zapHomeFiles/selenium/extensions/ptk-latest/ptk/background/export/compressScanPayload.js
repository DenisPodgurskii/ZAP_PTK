function ensureCompressionSupport() {
    if (typeof CompressionStream !== "function") {
        throw new Error("Gzip compression is not supported by this browser runtime.")
    }
}

async function gzipBytes(bytes) {
    ensureCompressionSupport()
    const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"))
    const buf = await new Response(stream).arrayBuffer()
    return new Uint8Array(buf)
}

export async function compressScanPayload(payload) {
    const json = JSON.stringify(payload)
    const bytes = new TextEncoder().encode(json)
    const compressed = await gzipBytes(bytes)
    return {
        body: compressed,
        contentType: "application/gzip",
        compression: "gzip"
    }
}

export default compressScanPayload
