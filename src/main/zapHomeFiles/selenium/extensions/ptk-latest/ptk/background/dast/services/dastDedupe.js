export function dastSimpleFingerprint(rawRequest, response) {
    const raw = typeof rawRequest === "object" ? rawRequest.raw : rawRequest
    const parts = (raw ? raw.split(/\r?\n/)[0] : "").trim().split(/\s+/)
    const method = (parts[0] || "GET").toUpperCase()
    const objectUrl = typeof rawRequest === "object" ? (rawRequest.url || rawRequest.requestUrl || null) : null
    const urlPart = parts[1] || objectUrl || (typeof rawRequest === "object" ? (rawRequest.ui_url || rawRequest.uiUrl) : null) || response?.url || response?.ui_url || "/"
    const base = response?.url || urlPart
    try {
        const url = new URL(urlPart, urlPart?.startsWith("http") ? undefined : base || "http://localhost")
        const names = new Set(); url.searchParams.forEach((_, key) => names.add(key.toLowerCase()))
        const out = ["http", url.host.toLowerCase(), (url.pathname || "/").replace(/\/+/g, "/"), method]
        if (names.size) out.push(`q:${Array.from(names).sort().join("&")}`)
        return out.join("|")
    } catch (_) { return "" }
}
