import { parseDownloadedScanPayload } from "./parseDownloadedScanPayload.js"

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
    if (!file || typeof file.arrayBuffer !== "function") {
        const err = new Error("Invalid file payload.")
        err.code = "invalid_file"
        throw err
    }

    const filename = String(file?.name || "")
    const lowerName = filename.toLowerCase()
    const isGzipByName = lowerName.endsWith(".gz") || lowerName.endsWith(".gzip")
    const contentType = String(file?.type || (isGzipByName ? "application/gzip" : "application/json"))

    const responseLike = {
        async arrayBuffer() {
            return file.arrayBuffer()
        },
        headers: headerLookup({
            "content-type": contentType,
            "content-disposition": filename ? `attachment; filename="${filename}"` : ""
        })
    }

    return parseDownloadedScanPayload(responseLike, options)
}

export default parseUploadedScanFile
