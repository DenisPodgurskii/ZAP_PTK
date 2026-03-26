function cloneValue(value) {
    if (typeof globalThis.structuredClone === "function") {
        try {
            return globalThis.structuredClone(value)
        } catch (_) {
            // fall back to JSON clone
        }
    }
    return JSON.parse(JSON.stringify(value ?? null))
}

function parseCandidateParamKey(paramKey = "") {
    const raw = String(paramKey || "").trim()
    if (!raw || !raw.includes(":")) {
        return {
            location: "param",
            name: ""
        }
    }
    const idx = raw.indexOf(":")
    return {
        location: raw.slice(0, idx).trim().toLowerCase() || "param",
        name: raw.slice(idx + 1).trim()
    }
}

function getNestedValue(target, path = "") {
    if (!target || typeof target !== "object") return undefined
    const normalized = String(path || "").trim()
    if (!normalized) return undefined
    return normalized.split(".").reduce((acc, part) => {
        if (!acc || typeof acc !== "object") return undefined
        return acc[part]
    }, target)
}

function setNestedValue(target, path = "", value) {
    if (!target || typeof target !== "object") return false
    const normalized = String(path || "").trim()
    if (!normalized) return false
    const parts = normalized.split(".").filter(Boolean)
    if (!parts.length) return false
    let cursor = target
    for (let index = 0; index < parts.length - 1; index += 1) {
        const part = parts[index]
        if (!cursor[part] || typeof cursor[part] !== "object" || Array.isArray(cursor[part])) {
            cursor[part] = {}
        }
        cursor = cursor[part]
    }
    cursor[parts[parts.length - 1]] = value
    return true
}

function parseUrlSearch(url = "") {
    try {
        const parsed = new URL(String(url || ""))
        return parsed
    } catch (_) {
        return null
    }
}

function parseBodyAsJson(body = "") {
    const raw = String(body || "").trim()
    if (!raw) return null
    try {
        const parsed = JSON.parse(raw)
        return parsed && typeof parsed === "object" ? parsed : null
    } catch (_) {
        return null
    }
}

function stringifyJsonBody(value) {
    try {
        return JSON.stringify(value)
    } catch (_) {
        return ""
    }
}

function parseBodyAsForm(body = "") {
    const raw = String(body || "").trim()
    if (!raw) return null
    try {
        return new URLSearchParams(raw)
    } catch (_) {
        return null
    }
}

function detectValueKind(value) {
    const raw = String(value ?? "").trim()
    if (!raw) return "empty"
    if (/^\d+$/.test(raw)) return "integer"
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(raw)) return "uuid"
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(raw)) return "email"
    if (/^[a-z0-9_-]{3,}$/i.test(raw)) return "slug"
    return "string"
}

function suggestSwapValue(value, location = "param") {
    const raw = String(value ?? "")
    const kind = detectValueKind(raw)
    if (kind === "integer") {
        const parsed = Number(raw)
        return {
            kind,
            strategy: "increment",
            swappedValue: String(Number.isFinite(parsed) ? parsed + 1 : 1)
        }
    }
    if (kind === "uuid") {
        const suffix = raw.slice(-1).toLowerCase()
        const next = suffix === "a" ? "b" : "a"
        return {
            kind,
            strategy: "uuid_tail_flip",
            swappedValue: `${raw.slice(0, -1)}${next}`
        }
    }
    if (kind === "email") {
        const atIndex = raw.indexOf("@")
        const local = atIndex > -1 ? raw.slice(0, atIndex) : raw
        const domain = atIndex > -1 ? raw.slice(atIndex + 1) : "example.test"
        return {
            kind,
            strategy: "email_alias",
            swappedValue: `${local}+alt@${domain}`
        }
    }
    if (kind === "slug") {
        return {
            kind,
            strategy: "slug_suffix",
            swappedValue: `${raw}-alt`
        }
    }
    if (location === "header") {
        return {
            kind,
            strategy: "header_variant",
            swappedValue: `${raw || "alt"}-alt`
        }
    }
    return {
        kind,
        strategy: "replace_with_alt",
        swappedValue: raw ? `${raw}-alt` : "2"
    }
}

function resolveExplicitTarget(spec = null, fallback = {}) {
    const input = spec && typeof spec === "object" ? spec : {}
    const location = String(input?.location || fallback?.location || "param").trim().toLowerCase() || "param"
    const name = String(input?.targetParam || input?.name || fallback?.name || "").trim()
    return {
        location,
        name
    }
}

function findPathSwapCandidate(url = "", preferredName = "") {
    const parsed = parseUrlSearch(url)
    if (!parsed) return null
    const pathname = parsed.pathname || "/"
    const segments = pathname.split("/")
    let chosenIndex = -1
    let chosenValue = ""
    for (let index = 0; index < segments.length; index += 1) {
        const segment = segments[index]
        if (!segment) continue
        if (preferredName && segment.toLowerCase() === String(preferredName).toLowerCase()) continue
        const kind = detectValueKind(segment)
        if (kind === "integer" || kind === "uuid") {
            chosenIndex = index
            chosenValue = segment
            break
        }
    }
    if (chosenIndex === -1) return null
    return {
        location: "path",
        name: preferredName || `segment_${chosenIndex}`,
        originalValue: chosenValue,
        pathIndex: chosenIndex
    }
}

export class ObjectSwapService {
    suggest({ candidate = null, requestSeed = null, objectSwap = null } = {}) {
        const parsedCandidate = parseCandidateParamKey(candidate?.paramKey || candidate?.targetParam?.key || "")
        const explicit = resolveExplicitTarget(objectSwap, parsedCandidate)
        const seed = requestSeed && typeof requestSeed === "object" ? cloneValue(requestSeed) : null
        if (!seed || !seed?.url) {
            return {
                applied: false,
                reason: "request_seed_unavailable",
                targetParam: explicit.name || parsedCandidate.name || null,
                location: explicit.location || parsedCandidate.location || "param"
            }
        }

        if (explicit.location === "query" && explicit.name) {
            const parsedUrl = parseUrlSearch(seed.url)
            const originalValue = parsedUrl?.searchParams?.get(explicit.name)
            if (originalValue !== null && originalValue !== undefined) {
                const suggestion = suggestSwapValue(originalValue, "query")
                return {
                    applied: false,
                    location: "query",
                    targetParam: explicit.name,
                    originalValue,
                    swappedValue: String(objectSwap?.swappedValue ?? suggestion.swappedValue),
                    strategy: String(objectSwap?.strategy || suggestion.strategy || "query_swap")
                }
            }
        }

        if ((explicit.location === "json" || explicit.location === "body") && explicit.name) {
            const parsedBody = parseBodyAsJson(seed.body)
            const originalValue = parsedBody ? getNestedValue(parsedBody, explicit.name) : undefined
            if (originalValue !== undefined) {
                const suggestion = suggestSwapValue(originalValue, explicit.location)
                return {
                    applied: false,
                    location: explicit.location,
                    targetParam: explicit.name,
                    originalValue,
                    swappedValue: String(objectSwap?.swappedValue ?? suggestion.swappedValue),
                    strategy: String(objectSwap?.strategy || suggestion.strategy || "json_swap")
                }
            }
        }

        if ((explicit.location === "form" || explicit.location === "body") && explicit.name) {
            const form = parseBodyAsForm(seed.body)
            const originalValue = form?.get(explicit.name)
            if (originalValue !== null && originalValue !== undefined) {
                const suggestion = suggestSwapValue(originalValue, "form")
                return {
                    applied: false,
                    location: form && explicit.location === "body" ? "form" : explicit.location,
                    targetParam: explicit.name,
                    originalValue,
                    swappedValue: String(objectSwap?.swappedValue ?? suggestion.swappedValue),
                    strategy: String(objectSwap?.strategy || suggestion.strategy || "form_swap")
                }
            }
        }

        if (explicit.location === "header" && explicit.name) {
            const headerName = Object.keys(seed.headers || {}).find((key) => key.toLowerCase() === explicit.name.toLowerCase())
            const originalValue = headerName ? seed.headers[headerName] : undefined
            if (originalValue !== undefined) {
                const suggestion = suggestSwapValue(originalValue, "header")
                return {
                    applied: false,
                    location: "header",
                    targetParam: headerName || explicit.name,
                    originalValue,
                    swappedValue: String(objectSwap?.swappedValue ?? suggestion.swappedValue),
                    strategy: String(objectSwap?.strategy || suggestion.strategy || "header_swap")
                }
            }
        }

        const pathCandidate = findPathSwapCandidate(seed.url, explicit.name)
        if (pathCandidate) {
            const suggestion = suggestSwapValue(pathCandidate.originalValue, "path")
            return {
                applied: false,
                location: "path",
                targetParam: pathCandidate.name,
                originalValue: pathCandidate.originalValue,
                swappedValue: String(objectSwap?.swappedValue ?? suggestion.swappedValue),
                strategy: String(objectSwap?.strategy || suggestion.strategy || "path_swap"),
                pathIndex: pathCandidate.pathIndex
            }
        }

        return {
            applied: false,
            reason: "swap_target_not_found",
            targetParam: explicit.name || parsedCandidate.name || null,
            location: explicit.location || parsedCandidate.location || "param"
        }
    }

    apply(requestSeed = null, candidate = null, objectSwap = null) {
        const seed = requestSeed && typeof requestSeed === "object" ? cloneValue(requestSeed) : null
        if (!seed || !seed?.url) {
            return {
                requestSeed: seed,
                objectSwap: {
                    applied: false,
                    reason: "request_seed_unavailable"
                }
            }
        }
        const suggested = this.suggest({ candidate, requestSeed: seed, objectSwap })
        if (!suggested?.targetParam || suggested?.swappedValue === undefined || suggested?.swappedValue === null) {
            return {
                requestSeed: seed,
                objectSwap: {
                    ...suggested,
                    applied: false
                }
            }
        }

        const nextSeed = cloneValue(seed)
        const swappedValue = String(objectSwap?.swappedValue ?? suggested.swappedValue)
        let applied = false

        if (suggested.location === "query") {
            const parsedUrl = parseUrlSearch(nextSeed.url)
            if (parsedUrl) {
                parsedUrl.searchParams.set(suggested.targetParam, swappedValue)
                nextSeed.url = parsedUrl.toString()
                applied = true
            }
        } else if (suggested.location === "json" || suggested.location === "body") {
            const parsedBody = parseBodyAsJson(nextSeed.body)
            if (parsedBody && setNestedValue(parsedBody, suggested.targetParam, swappedValue)) {
                nextSeed.body = stringifyJsonBody(parsedBody)
                applied = true
            }
        }

        if (!applied && (suggested.location === "form" || suggested.location === "body")) {
            const form = parseBodyAsForm(nextSeed.body)
            if (form) {
                form.set(suggested.targetParam, swappedValue)
                nextSeed.body = form.toString()
                applied = true
            }
        }

        if (!applied && suggested.location === "header") {
            const existingKey = Object.keys(nextSeed.headers || {}).find((key) => key.toLowerCase() === suggested.targetParam.toLowerCase())
            const headerKey = existingKey || suggested.targetParam
            nextSeed.headers = {
                ...(nextSeed.headers || {}),
                [headerKey]: swappedValue
            }
            applied = true
        }

        if (!applied && suggested.location === "path") {
            const parsedUrl = parseUrlSearch(nextSeed.url)
            if (parsedUrl) {
                const segments = parsedUrl.pathname.split("/")
                const pathIndex = Number.isInteger(suggested.pathIndex) ? suggested.pathIndex : -1
                if (pathIndex > -1 && pathIndex < segments.length) {
                    segments[pathIndex] = swappedValue
                    parsedUrl.pathname = segments.join("/")
                    nextSeed.url = parsedUrl.toString()
                    applied = true
                }
            }
        }

        return {
            requestSeed: nextSeed,
            objectSwap: {
                ...suggested,
                swappedValue,
                applied
            }
        }
    }
}

export default ObjectSwapService
