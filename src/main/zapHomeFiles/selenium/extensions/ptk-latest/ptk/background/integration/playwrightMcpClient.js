const DEFAULT_BASE_URL = "http://127.0.0.1:8787"
const DEFAULT_TIMEOUT_MS = 15000

function trimTrailingSlash(value) {
    return String(value || "").trim().replace(/\/+$/, "")
}

function resolveBaseUrl(settings = {}) {
    const automation = settings?.automation && typeof settings.automation === "object"
        ? settings.automation
        : {}
    const base = automation.playwrightMcpBaseUrl
        || automation.mcpBaseUrl
        || DEFAULT_BASE_URL
    return trimTrailingSlash(base) || DEFAULT_BASE_URL
}

async function fetchJson(url, opts = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
        let response
        try {
            response = await fetch(url, {
                ...opts,
                signal: controller.signal
            })
        } catch (err) {
            const message = err?.name === "AbortError"
                ? `Playwright MCP request timed out after ${timeoutMs}ms: ${url}`
                : `Playwright MCP is unreachable at ${url}. Start a local MCP runner exposing /v1/jobs.`
            const wrapped = new Error(message)
            wrapped.cause = err
            throw wrapped
        }
        const text = await response.text()
        let body = null
        try {
            body = text ? JSON.parse(text) : null
        } catch (_) {
            body = text
        }
        if (!response.ok) {
            const message = body?.error || body?.message || `HTTP ${response.status}`
            const err = new Error(`Playwright MCP request failed: ${message}`)
            err.status = response.status
            err.body = body
            throw err
        }
        return body
    } finally {
        clearTimeout(timer)
    }
}

export class PlaywrightMcpClient {
    constructor({ settings = {} } = {}) {
        this.settings = settings
    }

    getBaseUrl() {
        return resolveBaseUrl(this.settings)
    }

    async createJob(payload = {}) {
        const baseUrl = this.getBaseUrl()
        return fetchJson(`${baseUrl}/v1/jobs`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-PTK-Schema-Version": String(payload?.schemaVersion || "1.0.0")
            },
            body: JSON.stringify(payload || {})
        })
    }

    async getJob(jobId) {
        const id = String(jobId || "").trim()
        if (!id) {
            throw new Error("Playwright MCP jobId is required")
        }
        const baseUrl = this.getBaseUrl()
        return fetchJson(`${baseUrl}/v1/jobs/${encodeURIComponent(id)}`, {
            method: "GET",
            headers: {
                "Accept": "application/json",
                "X-PTK-Schema-Version": "1.0.0"
            }
        })
    }
}

export default PlaywrightMcpClient
