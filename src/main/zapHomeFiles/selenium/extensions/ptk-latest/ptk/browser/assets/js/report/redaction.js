const JWT_REGEX = /([A-Za-z0-9_-]{10,})\.([A-Za-z0-9_-]{10,})\.([A-Za-z0-9_-]{10,})/g
const TOKEN_KEY_REGEX = /(token|access[_-]?token|refresh[_-]?token|id[_-]?token|jwt|session)/i

function maskToken(value, { includeSensitiveEvidence = false } = {}) {
    if (!value) return "[REDACTED]"
    const str = String(value)
    if (!includeSensitiveEvidence) return "[REDACTED]"
    const head = str.slice(0, 10)
    const tail = str.slice(-6)
    if (!head || !tail) return "[REDACTED]"
    return `${head}...${tail}`
}

function redactJwt(text, opts) {
    if (!text) return text
    return String(text).replace(JWT_REGEX, (match) => maskToken(match, opts))
}

function redactBearer(text, opts) {
    if (!text) return text
    return String(text).replace(/Bearer\s+([A-Za-z0-9._-]+)/gi, (match, token) => {
        return `Bearer ${maskToken(token, opts)}`
    })
}

function redactTokenAssignments(text, opts) {
    if (!text) return text
    return String(text).replace(
        /(access[_-]?token|refresh[_-]?token|id[_-]?token|token|jwt|session)\s*[:=]\s*([A-Za-z0-9._-]{10,})/gi,
        (match, key, token) => `${key}: ${maskToken(token, opts)}`
    )
}

function redactCookieHeaderValue(value, opts) {
    if (!value) return value
    const parts = String(value).split(";")
    const redacted = parts.map((part, index) => {
        const trimmed = part.trim()
        if (!trimmed.includes("=")) return part
        if (index === 0) {
            const [name] = trimmed.split("=", 1)
            return `${name}=${maskToken(trimmed.slice(name.length + 1), opts)}`
        }
        return part
    })
    return redacted.join("; ")
}

export function redactText(text, opts = {}) {
    if (text === null || text === undefined) return text
    let result = String(text)
    result = redactBearer(result, opts)
    result = redactJwt(result, opts)
    result = redactTokenAssignments(result, opts)
    return result
}

export function redactHeaders(headers, opts = {}) {
    if (!headers) return headers
    if (Array.isArray(headers)) {
        return headers.map(entry => {
            const name = entry?.name || entry?.key || ""
            const value = entry?.value
            if (/^authorization$/i.test(name)) {
                return { ...entry, value: `Bearer ${maskToken(value, opts)}` }
            }
            if (/^cookie$/i.test(name) || /^set-cookie$/i.test(name)) {
                return { ...entry, value: redactCookieHeaderValue(value, opts) }
            }
            return { ...entry, value: redactText(value, opts) }
        })
    }
    if (typeof headers === "object") {
        const copy = {}
        Object.keys(headers).forEach(key => {
            const value = headers[key]
            if (/^authorization$/i.test(key)) {
                copy[key] = `Bearer ${maskToken(value, opts)}`
            } else if (/^cookie$/i.test(key) || /^set-cookie$/i.test(key)) {
                copy[key] = redactCookieHeaderValue(value, opts)
            } else {
                copy[key] = redactText(value, opts)
            }
        })
        return copy
    }
    return redactText(headers, opts)
}

function walkAndRedact(value, opts, keyHint = "") {
    if (value === null || value === undefined) return value
    if (typeof value === "string") {
        if (TOKEN_KEY_REGEX.test(String(keyHint))) {
            return maskToken(String(value), opts)
        }
        return redactText(String(value), opts)
    }
    if (typeof value === "number" || typeof value === "boolean") {
        if (TOKEN_KEY_REGEX.test(String(keyHint))) {
            return maskToken(String(value), opts)
        }
        return value
    }
    if (Array.isArray(value)) {
        return value.map(item => walkAndRedact(item, opts, keyHint))
    }
    if (typeof value === "object") {
        const copy = {}
        Object.keys(value).forEach(key => {
            copy[key] = walkAndRedact(value[key], opts, key)
        })
        return copy
    }
    return value
}

export function redactStorage(storageDump, opts = {}) {
    if (!storageDump || typeof storageDump !== "object") return storageDump
    return walkAndRedact(storageDump, opts)
}

export function redactEvidence(evidenceObj, opts = {}) {
    if (!evidenceObj || typeof evidenceObj !== "object") return evidenceObj
    return walkAndRedact(evidenceObj, opts)
}
