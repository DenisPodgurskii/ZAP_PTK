import { loadDevLocalConfig } from "./devLocalConfig.js"

export const PORTAL_BASE_URL = "https://pentestkit.pro"

let runtimePortalBaseUrl = normalizePortalBaseUrl(PORTAL_BASE_URL, PORTAL_BASE_URL)

function normalizePathFragment(value, fallback = "") {
    const trimmed = String(value || "").trim()
    if (!trimmed) return fallback
    return trimmed.startsWith("/") ? trimmed : `/${trimmed}`
}

function withDefaultScheme(value) {
    const trimmed = String(value || "").trim()
    if (!trimmed) return ""
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
        return trimmed
    }
    return `http://${trimmed}`
}

export function normalizePortalBaseUrl(value, fallback = "") {
    const rawValue = String(value || "").trim()
    const fallbackValue = String(fallback || "").trim()
    const candidate = withDefaultScheme(rawValue || fallbackValue)
    if (!candidate) return ""
    try {
        const parsed = new URL(candidate)
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
            return withDefaultScheme(fallbackValue)
        }
        return parsed.origin
    } catch (_) {
        return withDefaultScheme(fallbackValue)
    }
}

export function getPortalBaseUrl() {
    return runtimePortalBaseUrl || PORTAL_BASE_URL
}

export async function initializePortalRuntimeConfig({ force = false } = {}) {
    const devLocal = await loadDevLocalConfig({ force })
    runtimePortalBaseUrl = normalizePortalBaseUrl(devLocal?.portalBaseUrl, PORTAL_BASE_URL)
    return { baseUrl: getPortalBaseUrl() }
}

export function buildPortalUrl(endpoint, { baseUrl = null, apiBase = "/api/v1" } = {}) {
    const resolvedBaseUrl = normalizePortalBaseUrl(baseUrl, getPortalBaseUrl())
    const resolvedEndpoint = normalizePathFragment(endpoint, "")
    if (!resolvedBaseUrl || !resolvedEndpoint) return null
    const resolvedApiBase = normalizePathFragment(apiBase, "/api/v1").replace(/\/+$/, "")
    return new URL(`${resolvedApiBase}${resolvedEndpoint}`, `${resolvedBaseUrl}/`).toString()
}

export function buildStoredCredentialPortalUrl(endpoint, { apiBase = "/api/v1" } = {}) {
    return buildPortalUrl(endpoint, { baseUrl: PORTAL_BASE_URL, apiBase })
}

export function isProductionPortalUrl(value) {
    try {
        return new URL(String(value || "")).origin === PORTAL_BASE_URL
    } catch (_) {
        return false
    }
}

export function buildPortalPageUrl(path, { baseUrl = null } = {}) {
    const resolvedBaseUrl = normalizePortalBaseUrl(baseUrl, getPortalBaseUrl())
    const resolvedPath = normalizePathFragment(path, "")
    if (!resolvedBaseUrl || !resolvedPath) return null
    return new URL(resolvedPath, `${resolvedBaseUrl}/`).toString()
}

export function buildPortalLoginUrl(options = {}) {
    return buildPortalPageUrl("/login", options)
}

export function buildPortalRegisterUrl(options = {}) {
    return buildPortalPageUrl("/register", options)
}

export function isLocalPortalBaseUrl(value) {
    const normalized = normalizePortalBaseUrl(value, "")
    if (!normalized) return false
    try {
        const hostname = new URL(normalized).hostname.toLowerCase()
        return hostname === "localhost"
            || hostname === "127.0.0.1"
            || hostname === "0.0.0.0"
            || hostname === "::1"
            || hostname.endsWith(".local")
    } catch (_) {
        return false
    }
}

export function assertReleasePortalBaseUrl(baseUrl = PORTAL_BASE_URL) {
    if (isLocalPortalBaseUrl(baseUrl)) {
        throw new Error(`[PTK] Refusing to build release artifacts with local portal base URL: ${baseUrl}`)
    }
    return true
}
