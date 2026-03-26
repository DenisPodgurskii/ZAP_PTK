import CryptoES from "../../packages/crypto-es/index.js"

export const PLAYWRIGHT_MCP_SCHEMA_VERSION = "1.0.0"
export const PLAYWRIGHT_MCP_JOB_TYPE = "PLAYWRIGHT_CANDIDATE_RUN"

function hashHex(value) {
    return CryptoES.SHA256(String(value || "")).toString(CryptoES.enc.Hex)
}

function normalizeMethod(value) {
    const method = String(value || "GET").trim().toUpperCase()
    return method || "GET"
}

function normalizePathTemplate(path) {
    const raw = String(path || "/").trim() || "/"
    const withLeadingSlash = raw.startsWith("/") ? raw : `/${raw}`
    return withLeadingSlash.replace(/:([a-zA-Z0-9_]+)/g, "1")
}

function parseRouteKey(routeKey = "", fallbackHost = null) {
    const parts = String(routeKey || "").split("|")
    if (parts.length < 3) {
        return {
            host: String(fallbackHost || "").trim() || null,
            method: "GET",
            pathTemplate: "/"
        }
    }
    return {
        host: String(parts[0] || "").trim() || String(fallbackHost || "").trim() || null,
        method: normalizeMethod(parts[1] || "GET"),
        pathTemplate: normalizePathTemplate(parts.slice(2).join("|"))
    }
}

function buildDefaultHeaders(method = "GET", existing = {}) {
    const headers = {}
    Object.entries(existing || {}).forEach(([name, value]) => {
        const key = String(name || "").trim().toLowerCase()
        if (!key) return
        headers[key] = String(value ?? "")
    })
    const normalizedMethod = normalizeMethod(method)
    if (!headers["accept"]) {
        headers["accept"] = "application/json, text/plain, */*"
    }
    if (!headers["content-type"] && ["POST", "PUT", "PATCH"].includes(normalizedMethod)) {
        headers["content-type"] = "application/json"
    }
    return headers
}

function normalizeRequestSeed(seed = null, route = {}, scheme = "http") {
    const host = String(route?.host || "").trim()
    const method = normalizeMethod(seed?.method || route?.method || "GET")
    const path = normalizePathTemplate(seed?.path || route?.pathTemplate || "/")
    const baseUrl = `${scheme}://${host}`
    const seedUrl = String(seed?.url || "").trim()
    const url = seedUrl || `${baseUrl}${path}`
    const body = seed?.body === undefined || seed?.body === null ? "" : String(seed.body)
    return {
        seedType: seedUrl ? "captured_request" : "synthesized_route",
        method,
        url,
        headers: buildDefaultHeaders(method, seed?.headers || {}),
        body,
        cookies: Array.isArray(seed?.cookies) ? seed.cookies : [],
        sourceEvidence: seed?.sourceEvidence || null
    }
}

function resolveConstraints(profile = "smoke", overrides = {}) {
    const normalized = String(profile || "smoke").toLowerCase()
    const profileDefaults = normalized === "deep"
        ? { maxDurationMs: 300000, maxRequests: 150, maxMutations: 50 }
        : { maxDurationMs: 120000, maxRequests: 60, maxMutations: 20 }
    return {
        maxDurationMs: Number(overrides?.maxDurationMs || profileDefaults.maxDurationMs),
        maxRequests: Number(overrides?.maxRequests || profileDefaults.maxRequests),
        maxMutations: Number(overrides?.maxMutations || profileDefaults.maxMutations),
        stopOnCriticalCrash: overrides?.stopOnCriticalCrash !== false,
        nonDestructive: overrides?.nonDestructive !== false
    }
}

function resolveMutationValues(candidate = {}) {
    const location = String(candidate?.targetParam?.location || "param").toLowerCase()
    if (location === "header") {
        return ["application/json", "application/graphql", "text/plain"]
    }
    return ["0", "1", "2147483647", "\"'<>", "../"]
}

function resolveJobId(candidate = {}, scanId = null) {
    const payload = [
        candidate?.id || "",
        candidate?.suppressKey || "",
        candidate?.routeKey || "",
        scanId || "",
        Date.now()
    ].join("|")
    return `mcpjob_${hashHex(payload).slice(0, 24)}`
}

function normalizeCookieEntry(cookie = {}) {
    return {
        name: String(cookie?.name || "").trim(),
        value: String(cookie?.value || ""),
        domain: String(cookie?.domain || "").trim(),
        path: String(cookie?.path || "/").trim() || "/",
        secure: cookie?.secure === true,
        httpOnly: cookie?.httpOnly === true,
        sameSite: String(cookie?.sameSite || "no_restriction").trim() || "no_restriction",
        expires: Number.isFinite(Number(cookie?.expirationDate)) ? Number(cookie.expirationDate) : null
    }
}

function resolveAuthContext({
    authMode = "reuse_storage_state",
    authContext = null
} = {}) {
    if (!authContext || typeof authContext !== "object") {
        return {
            mode: String(authMode || "reuse_storage_state"),
            storageStateRef: "ptk_profile_default"
        }
    }
    const mode = String(authContext?.mode || authMode || "reuse_storage_state").trim() || "reuse_storage_state"
    const resolved = { mode }
    if (authContext?.storageStateRef) {
        resolved.storageStateRef = String(authContext.storageStateRef)
    } else if (mode === "reuse_storage_state") {
        resolved.storageStateRef = "ptk_profile_default"
    }
    if (authContext?.sessionProfileId) {
        resolved.sessionProfileId = String(authContext.sessionProfileId)
    }
    if (authContext?.sessionProfileLabel) {
        resolved.sessionProfileLabel = String(authContext.sessionProfileLabel)
    }
    if (Array.isArray(authContext?.cookieSnapshot) && authContext.cookieSnapshot.length) {
        resolved.cookieSnapshot = authContext.cookieSnapshot
            .map(normalizeCookieEntry)
            .filter((cookie) => cookie.name && cookie.domain)
    }
    return resolved
}

export function buildPlaywrightCandidateJob({
    scanResult = {},
    candidate = {},
    requestSeed = null,
    profile = "smoke",
    authMode = "reuse_storage_state",
    constraints = {},
    authContext = null
} = {}) {
    const route = parseRouteKey(candidate?.routeKey, scanResult?.host)
    if (!route.host) {
        throw new Error("Candidate host is not resolvable for Playwright run")
    }
    const scheme = String(candidate?.route?.scheme || requestSeed?.scheme || "http").toLowerCase() === "https"
        ? "https"
        : "http"
    const normalizedSeed = normalizeRequestSeed(requestSeed, route, scheme)
    const baseUrl = (() => {
        try {
            return new URL(normalizedSeed.url).origin
        } catch (_) {
            return `${scheme}://${route.host}`
        }
    })()
    const jobId = resolveJobId(candidate, scanResult?.scanId || null)
    const mutationParamKey = String(candidate?.targetParam?.key || candidate?.paramKey || "param").trim()
    const mutationLocation = String(candidate?.targetParam?.location || "param").trim().toLowerCase()

    return {
        schemaVersion: PLAYWRIGHT_MCP_SCHEMA_VERSION,
        jobType: PLAYWRIGHT_MCP_JOB_TYPE,
        jobId,
        requestedAt: new Date().toISOString(),
        source: {
            product: "PTK_EXTENSION",
            workspaceId: "ws_local",
            scanId: scanResult?.scanId || null,
            candidateId: candidate?.id || null,
            action: "RUN_IN_PLAYWRIGHT"
        },
        target: {
            baseUrl,
            allowedHosts: [route.host],
            blockedHosts: [],
            sameSiteOnly: true
        },
        candidate: {
            id: candidate?.id || null,
            ruleCode: candidate?.createdByRule || null,
            type: candidate?.type || null,
            routeKey: candidate?.routeKey || null,
            param: {
                key: mutationParamKey,
                location: mutationLocation
            },
            why: Array.isArray(candidate?.why) ? candidate.why : []
        },
        requestSeed: normalizedSeed,
        playbook: {
            mode: "hybrid",
            authContext: resolveAuthContext({ authMode, authContext }),
            steps: [
                { kind: "goto", url: `${baseUrl}/` },
                { kind: "request", from: "requestSeed" }
            ],
            mutations: [
                {
                    id: "m1",
                    paramKey: mutationParamKey,
                    location: mutationLocation,
                    values: resolveMutationValues(candidate)
                }
            ]
        },
        constraints: resolveConstraints(profile, constraints),
        artifacts: {
            captureNetwork: true,
            captureConsole: true,
            captureScreenshotOnError: true,
            captureTrace: true,
            captureVideo: false,
            redactionProfile: "ptk_default"
        },
        callbacks: {
            mode: "pull",
            resultTtlSec: 1800
        },
        meta: {
            ptkMcpSchemaVersion: PLAYWRIGHT_MCP_SCHEMA_VERSION,
            candidateRunKey: hashHex(`${candidate?.id || ""}|${candidate?.routeKey || ""}|${mutationParamKey}`).slice(0, 40),
            initiator: "user"
        }
    }
}

export default buildPlaywrightCandidateJob
