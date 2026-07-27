const runtimeAPI =
    typeof browser !== "undefined"
        ? browser
        : typeof chrome !== "undefined"
            ? chrome
            : null

const DEV_LOCAL_CONFIG_PATH = "dev.local.json"

let devLocalConfigPromise = null

function normalizeString(value) {
    return typeof value === "string" ? value.trim() : ""
}

function normalizeHttpOrigin(value) {
    const normalized = normalizeString(value)
    if (!normalized) return null
    try {
        const parsed = new URL(normalized)
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null
        return parsed.origin
    } catch (_) {
        return null
    }
}

function normalizeDevLocalConfig(payload) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        return {}
    }

    const normalized = {}
    if (payload.automationEnabled === true || payload.automation === true) {
        normalized.automationEnabled = true
    }
    if (payload.automationAllowChildFrameBootstrap === true) {
        normalized.automationAllowChildFrameBootstrap = true
    }
    if (Array.isArray(payload.automationChildFrameBootstrapOrigins)) {
        const origins = Array.from(new Set(
            payload.automationChildFrameBootstrapOrigins
                .map(normalizeHttpOrigin)
                .filter(Boolean)
        ))
        if (origins.length) {
            normalized.automationChildFrameBootstrapOrigins = origins
        }
    }

    const portalBaseUrl = normalizeString(payload.portalBaseUrl || payload.portalUrl)
    if (portalBaseUrl) {
        normalized.portalBaseUrl = portalBaseUrl
    }

    return normalized
}

async function fetchDevLocalConfig() {
    if (!runtimeAPI?.runtime?.getURL || typeof fetch !== "function") {
        return {}
    }

    let response = null
    try {
        response = await fetch(runtimeAPI.runtime.getURL(DEV_LOCAL_CONFIG_PATH), {
            cache: "no-cache"
        })
    } catch (err) {
        return {}
    }

    if (!response?.ok) {
        return {}
    }

    try {
        const payload = await response.json()
        return normalizeDevLocalConfig(payload)
    } catch (err) {
        const message = err?.message || String(err)
        if (message) {
            console.warn("[PTK] Unable to parse dev.local.json:", message)
        }
        return {}
    }
}

export function getDevLocalConfigPath() {
    return DEV_LOCAL_CONFIG_PATH
}

export async function loadDevLocalConfig({ force = false } = {}) {
    if (force || !devLocalConfigPromise) {
        devLocalConfigPromise = fetchDevLocalConfig()
    }
    return devLocalConfigPromise
}
