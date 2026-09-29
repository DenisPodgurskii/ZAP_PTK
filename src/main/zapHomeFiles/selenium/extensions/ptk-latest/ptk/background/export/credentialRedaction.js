// Export-copy processing only: no ambient credentials, engine mutation or
// cross-export cache. Decoding is one format layer, never recursive guessing.
const MASK = "[REDACTED]"
const AMBIGUOUS_LITERALS = new Set(["true", "false", "null", "undefined"])
const IDENTITIES = new Set(["id", "scanId", "findingId", "groupId", "ruleId", "moduleId", "engine", "severity", "type", "version"])

export function isCredentialKey(key) {
    const name = String(key || "").split(/[.\[\]]/).filter(Boolean).at(-1) || ""
    const normalized = name.replace(/[^a-z0-9]/gi, "").toLowerCase()
    return /^(?:x)?(?:password|passwd|pwd|secret|clientsecret|apikey|accesskey|token|accesstoken|refreshtoken|idtoken|sessiontoken|csrftoken|xsrftoken|authorization|proxyauthorization|authtoken|credential|credentials|cookie|setcookie)$/.test(normalized)
}

function walk(root, visit) {
    const pending = [root]
    const seen = new WeakSet()
    while (pending.length) {
        const object = pending.pop()
        if (!object || typeof object !== "object" || seen.has(object)) continue
        seen.add(object)
        visit(object)
        for (const value of Object.values(object)) {
            if (value && typeof value === "object") pending.push(value)
        }
    }
}

function decodeForm(value) {
    try { return decodeURIComponent(value.replace(/\+/g, " ")) } catch (_) { return value }
}

function parameters(text, onSecret, masking, url = false) {
    // Keep untouched bytes/order/duplicate parameters, including SPA queries.
    return text.replace(url ? /([?&#])([^?&#=\s]+)=([^&#\s]*)/g : /(^|&)([^&=\s]+)=([^&\r\n]*)/g,
        (all, prefix, key, value) => {
            if (!isCredentialKey(decodeForm(key))) return all
            onSecret(decodeForm(value))
            return masking ? `${prefix}${key}=${MASK}` : all
        })
}

function structured(root, onSecret, masking, cookies = false) {
    walk(root, object => {
        if ((cookies || isCredentialKey(object.name || object.key)) && Object.hasOwn(object, "value")) {
            onSecret(object.value)
            if (masking) object.value = MASK
        }
        for (const key of Object.keys(object)) {
            if (!isCredentialKey(key) || object[key] == null) continue
            const value = object[key]
            onSecret(value)
            // Collection walks nested objects once; masking may remove a whole
            // credential container only after that separate collection pass.
            if (masking) object[key] = MASK
        }
    })
}

function bodyCarrier(text, onSecret, masking) {
    const trimmed = text.trimStart()
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        let parsed
        try {
            parsed = JSON.parse(text)
        } catch (_) {
            // Do not treat malformed JSON as a successfully sanitized object.
            // Known literal spans are still masked by the enclosing tree pass.
            if (masking) {
                for (const match of text.matchAll(/"((?:[^"\\]|\\.)*)"\s*:/g)) {
                    try { if (isCredentialKey(JSON.parse(`"${match[1]}"`))) return MASK } catch (_) { }
                }
            }
            return text
        }
        let changed = false
        structured(parsed, value => { changed = true; onSecret(value) }, masking)
        return masking && changed ? JSON.stringify(parsed) : text
    }
    return parameters(text, onSecret, masking)
}

function headerSecrets(name, value, onSecret) {
    if (typeof value !== "string" || !isCredentialKey(name)) return
    onSecret(value)
    if (/^(?:proxy-)?authorization$/i.test(name)) onSecret(value.trim().replace(/^\S+\s+/, ""))
    if (/^(?:set-)?cookie$/i.test(name)) {
        const pairs = /^set-cookie$/i.test(name) ? [value.split(";")[0]] : value.split(";")
        for (const pair of pairs) {
            const equal = pair.indexOf("=")
            if (equal > 0) onSecret(pair.slice(equal + 1).trim())
        }
    }
}

function httpCarrier(text, onSecret, masking) {
    if (!/^(?:[A-Z]+\s+\S+\s+HTTP\/\d|HTTP\/\d)/.test(text)) return null
    const boundary = /\r?\n\r?\n/.exec(text)
    const head = boundary ? text.slice(0, boundary.index) : text
    const lines = head.split(/(\r?\n)/)
    lines[0] = parameters(lines[0], onSecret, masking, true)
    for (let i = 2; i < lines.length; i += 2) {
        const header = /^([^:\s]+):(.*)$/.exec(lines[i])
        if (!header || !isCredentialKey(header[1])) continue
        const value = header[2].trim()
        headerSecrets(header[1], value, onSecret)
        if (masking) lines[i] = `${header[1]}: ${MASK}`
    }
    if (!boundary) return lines.join("")
    return lines.join("") + boundary[0] + bodyCarrier(text.slice(boundary.index + boundary[0].length), onSecret, masking)
}

function carrier(text, key, onSecret, masking) {
    if (key === "raw") {
        const http = httpCarrier(text, onSecret, masking)
        if (http !== null) return http
    }
    if (key === "url" || key === "ui_url") return parameters(text, onSecret, masking, true)
    if (key === "body" || key === "text") return bodyCarrier(text, onSecret, masking)
    return text
}

function variants(value) {
    const forms = new Set([value, JSON.stringify(value).slice(1, -1)])
    forms.add(JSON.stringify(value).slice(1, -1).replace(/\//g, "\\/"))
    try {
        const encoded = encodeURIComponent(value)
        forms.add(encoded)
        forms.add(encoded.replace(/%20/g, "+"))
        forms.add(encoded.replace(/%[0-9A-F]{2}/g, hex => hex.toLowerCase()))
        forms.add(encoded.replace(/%20/g, "+").replace(/%[0-9A-F]{2}/g, hex => hex.toLowerCase()))
        const form = new URLSearchParams({ value }).toString().slice("value=".length)
        forms.add(form)
        forms.add(form.replace(/%[0-9A-F]{2}/g, hex => hex.toLowerCase()))
    } catch (_) { /* Lone UTF-16 surrogates have no encodeURIComponent form. */ }
    return forms
}

// Aho-Corasick literal matching: do not rescan each evidence string for every
// credential or construct a data-dependent regular expression. Only the longest
// suffix match is needed; overlapping matches are merged into one redaction.
function literalMatcher(values) {
    const nodes = [{ next: new Map(), fail: 0, length: 0 }]
    for (const value of values) {
        for (const form of variants(value)) {
            let state = 0
            for (let i = 0; i < form.length; i++) {
                const char = form[i]
                if (!nodes[state].next.has(char)) {
                    nodes[state].next.set(char, nodes.length)
                    nodes.push({ next: new Map(), fail: 0, length: 0 })
                }
                state = nodes[state].next.get(char)
            }
            nodes[state].length = Math.max(nodes[state].length, form.length)
        }
    }
    const queue = [...nodes[0].next.values()]
    for (let i = 0; i < queue.length; i++) {
        const state = queue[i]
        for (const [char, child] of nodes[state].next) {
            let failure = nodes[state].fail
            while (failure && !nodes[failure].next.has(char)) failure = nodes[failure].fail
            nodes[child].fail = nodes[failure].next.get(char) || 0
            nodes[child].length = Math.max(nodes[child].length, nodes[nodes[child].fail].length)
            queue.push(child)
        }
    }
    return text => {
        let state = 0
        const ranges = []
        let markerEnd = -1
        for (let i = 0; i < text.length; i++) {
            if (text.startsWith(MASK, i)) markerEnd = i + MASK.length
            const char = text[i]
            while (state && !nodes[state].next.has(char)) state = nodes[state].fail
            state = nodes[state].next.get(char) || 0
            if (!nodes[state].length) continue
            let start = i + 1 - nodes[state].length
            // Already masked bytes are not a new credential occurrence, but a
            // longer credential containing a marker still matches normally.
            if (i < markerEnd && start >= markerEnd - MASK.length) continue
            while (ranges.length && ranges.at(-1)[1] >= start) start = Math.min(start, ranges.pop()[0])
            ranges.push([start, i + 1])
        }
        if (!ranges.length) return text
        const pieces = []
        let offset = 0
        for (const [start, end] of ranges) {
            pieces.push(text.slice(offset, start), MASK)
            offset = end
        }
        pieces.push(text.slice(offset))
        return pieces.join("")
    }
}

function collectCredentials(source) {
    const values = new Set()
    const add = value => {
        // Short values remain carrier-scoped: never replace 'x', 'true', etc.
        if (typeof value === "string" && value.length >= 4 && value.trim() && value !== MASK
            && !AMBIGUOUS_LITERALS.has(value.toLowerCase())) values.add(value)
    }
    structured(source, add, false)
    walk(source, object => {
        if (Array.isArray(object.cookies)) structured(object.cookies, add, false, true)
        if (object.headers) {
            if (Array.isArray(object.headers)) {
                for (const header of object.headers) if (header) headerSecrets(header.name || header.key, header.value, add)
            } else {
                for (const [key, value] of Object.entries(object.headers)) headerSecrets(key, value, add)
            }
        }
        for (const [key, value] of Object.entries(object)) {
            if (typeof value === "string") carrier(value, key, add, false)
        }
    })
    return values
}

export function createCredentialRedactor(source) {
    // Prefer baseline credentials before whole mutated values found in attack
    // bodies. This retains injection operators around a known original secret.
    const originals = Array.isArray(source?.requests) ? source.requests.map(request => request?.original) : []
    const replaceOriginal = literalMatcher(collectCredentials(originals))
    const replaceOther = literalMatcher(collectCredentials(source))
    const replace = value => replaceOther(replaceOriginal(value))
    return (root, { maskPayloads = true } = {}) => {
        walk(root, object => {
            if (Array.isArray(object.cookies)) structured(object.cookies, () => {}, true, true)
            const parameter = typeof object.param === "object" ? object.param?.name || object.param?.key : object.param
            if (maskPayloads && isCredentialKey(parameter) && typeof object.payload === "string") {
                const masked = replace(object.payload)
                object.payload = masked === object.payload ? MASK : masked
            }
            for (const [key, value] of Object.entries(object)) {
                if (typeof value === "string" && !IDENTITIES.has(key)) {
                    object[key] = replace(carrier(value, key, () => {}, true))
                }
            }
        })
        structured(root, () => {}, true)
        return root
    }
}
