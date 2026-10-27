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

function requestHeaderLines(rawRequest) {
    const raw = typeof rawRequest === 'string' ? rawRequest : rawRequest?.raw
    const headers = []
    if (typeof raw === 'string') {
        const boundary = raw.indexOf('\r\n\r\n')
        const fallbackBoundary = boundary < 0 ? raw.indexOf('\n\n') : boundary
        const head = fallbackBoundary < 0 ? raw : raw.slice(0, fallbackBoundary)
        for (const line of head.split(/\r?\n/).slice(1)) {
            const separator = line.indexOf(':')
            if (separator > 0) headers.push({ name: line.slice(0, separator), value: line.slice(separator + 1).trim() })
        }
    }
    if (typeof rawRequest === 'object' && rawRequest) {
        for (const entry of rawRequest.headers || rawRequest.capturedRequest?.requestHeaders || []) {
            if (entry?.name) headers.push(entry)
        }
    }
    return headers
}

function looksLikeJwt(value) {
    const token = String(value || '').trim().replace(/^"|"$/g, '')
    return /^[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]*={0,2}$/.test(token)
}

// Only carrier presence enters a key. Never include JWTs, credentials or their hashes.
export function dastAuthCarrierClass(rawRequest) {
    const raw = typeof rawRequest === 'string' ? rawRequest : rawRequest?.raw
    const firstLine = typeof raw === 'string' ? raw.split(/\r?\n/, 1)[0] : ''
    const method = String(rawRequest?.method || firstLine.split(/\s+/, 1)[0] || '').toUpperCase()
    if (method !== 'GET' && method !== 'HEAD') return ''
    let hasAuthorization = false
    let hasJwtCookie = false
    for (const header of requestHeaderLines(rawRequest)) {
        const name = String(header?.name || '').trim().toLowerCase()
        const value = String(header?.value || '').trim()
        if (name === 'authorization' && value) hasAuthorization = true
        if (name === 'cookie' && value) {
            hasJwtCookie ||= value.split(';').some(entry => looksLikeJwt(entry.slice(entry.indexOf('=') + 1)))
        }
    }
    if (Array.isArray(rawRequest?.cookies)) {
        hasJwtCookie ||= rawRequest.cookies.some(cookie => looksLikeJwt(cookie?.value))
    }
    return `${hasAuthorization ? 'h' : ''}${hasJwtCookie ? 'c' : ''}`
}

export function dastAuthAwareFingerprint(base, rawRequest, response) {
    if (!base) return base
    const type = String(rawRequest?.responseType || response?.type || response?.responseType || '').toLowerCase()
    if (!type || type === 'main_frame') return base
    const authClass = dastAuthCarrierClass(rawRequest)
    return authClass ? `${base}|auth:${authClass}` : base
}
