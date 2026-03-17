const UUID_SEGMENT_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const LONG_HEX_SEGMENT_RE = /^[0-9a-f]{16,}$/i
const NUMERIC_SEGMENT_RE = /^-?\d+$/
const BASE64ISH_SEGMENT_RE = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{20,}$/
const DEFAULT_HOST = "unknown-host"

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function normalizeHostHint(hostHint) {
    const raw = toNonEmptyString(hostHint)
    if (!raw) return null
    try {
        const parsed = new URL(raw.includes("://") ? raw : `http://${raw}`)
        return parsed.host ? String(parsed.host).toLowerCase() : null
    } catch (_) {
        return String(raw).toLowerCase().replace(/^\.+/, "").replace(/\/+$/, "")
    }
}

function parseUrl(rawUrl, hostHint = null) {
    const raw = toNonEmptyString(rawUrl)
    if (!raw) return null
    const host = normalizeHostHint(hostHint) || DEFAULT_HOST
    try {
        return new URL(raw, `http://${host}`)
    } catch (_) {
        return null
    }
}

function extractHashRoutePath(hashValue) {
    const raw = toNonEmptyString(hashValue)
    if (!raw) return null
    let normalized = raw.startsWith("#") ? raw.slice(1) : raw
    if (normalized.startsWith("!/")) {
        normalized = normalized.slice(1)
    }
    if (!normalized.startsWith("/")) return null
    const queryIdx = normalized.indexOf("?")
    const pathOnly = queryIdx >= 0 ? normalized.slice(0, queryIdx) : normalized
    return toNonEmptyString(pathOnly) || null
}

function normalizePathSegment(segment) {
    const value = toNonEmptyString(segment)
    if (!value) return ""
    if (NUMERIC_SEGMENT_RE.test(value)) return ":id"
    if (UUID_SEGMENT_RE.test(value)) return ":uuid"
    if (LONG_HEX_SEGMENT_RE.test(value)) return ":hex"
    if (BASE64ISH_SEGMENT_RE.test(value)) return ":token"
    if (value.length > 96) return ":blob"
    return value
}

export function normalizeMethod(method) {
    const raw = toNonEmptyString(method)
    if (!raw) return "GET"
    const upper = raw.toUpperCase()
    if (upper === "*") return "*"
    return upper
}

export function normalizeEngineName(engine) {
    const raw = toNonEmptyString(engine)
    if (!raw) return null
    const upper = raw.toUpperCase()
    if (upper === "DAST" || upper === "IAST" || upper === "SAST" || upper === "SCA") {
        return upper
    }
    return upper
}

export function templatePath(pathname) {
    const raw = toNonEmptyString(pathname) || "/"
    const parts = raw.split("/").filter(Boolean).map((part) => normalizePathSegment(part))
    if (!parts.length) return "/"
    return `/${parts.join("/")}`
}

export function buildRouteKey({ url, method, host } = {}) {
    const parsed = parseUrl(url, host)
    const hostPort = parsed?.host
        ? String(parsed.host).toLowerCase()
        : (normalizeHostHint(host) || DEFAULT_HOST)
    const normalizedMethod = normalizeMethod(method)
    const hashRoutePath = extractHashRoutePath(parsed?.hash)
    const logicalPath = hashRoutePath || parsed?.pathname || "/"
    const pathTemplate = templatePath(logicalPath)
    return `${hostPort}|${normalizedMethod}|${pathTemplate}`
}

export function buildRouteFamilyKey(routeKey) {
    const raw = toNonEmptyString(routeKey)
    if (!raw) return `${DEFAULT_HOST}|*|/`
    const parts = raw.split("|")
    const host = toNonEmptyString(parts[0]) || DEFAULT_HOST
    const path = toNonEmptyString(parts[2]) || "/"
    return `${host}|*|${path}`
}

export function normalizeParamKey(param, location = "param") {
    const loc = toNonEmptyString(location) || "param"
    const raw = toNonEmptyString(param)
    if (!raw) return `${loc}:<none>`
    return `${loc}:${raw}`
}

export function stableSortStrings(values = []) {
    return Array.from(values || [])
        .map((value) => String(value))
        .sort((a, b) => a.localeCompare(b))
}

export function splitRouteKey(routeKey) {
    const raw = toNonEmptyString(routeKey)
    if (!raw) {
        return { host: DEFAULT_HOST, method: "GET", pathTemplate: "/" }
    }
    const [host = DEFAULT_HOST, method = "GET", pathTemplate = "/"] = raw.split("|")
    return { host, method, pathTemplate }
}
