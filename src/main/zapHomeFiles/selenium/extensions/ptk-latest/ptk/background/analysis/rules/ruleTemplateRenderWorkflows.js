import { splitRouteKey, buildRouteKey, normalizeMethod, normalizeParamKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const MAX_BUCKETS = 2000
const MAX_CANDIDATES = 20
const MAX_EVIDENCE_REFS = 10
const TEMPLATE_ERROR_RE = /TemplateSyntaxError|Twig(?:\\Error|\s+Error)|Jinja2?|FreeMarker|Velocity(?:Exception)?|Handlebars|Mustache|Liquid|EJS|ERB|template error|unexpected end of template/i
const UUIDISH_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const NUMERIC_RE = /^-?\d+(?:\.\d+)?$/
const BOOLEAN_RE = /^(?:true|false|null)$/i

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function getHeaderValue(headers = [], headerName = "") {
    if (!Array.isArray(headers) || !headerName) return null
    const needle = String(headerName).toLowerCase()
    const match = headers.find((header) => String(header?.name || "").toLowerCase() === needle)
    const value = match?.value
    if (value === undefined || value === null) return null
    const str = String(value)
    return str.length ? str : null
}

function extractRawBody(rawRequest = "") {
    if (typeof rawRequest !== "string" || !rawRequest.length) return ""
    const splitCrlf = rawRequest.indexOf("\r\n\r\n")
    if (splitCrlf >= 0) return rawRequest.slice(splitCrlf + 4)
    const splitLf = rawRequest.indexOf("\n\n")
    if (splitLf >= 0) return rawRequest.slice(splitLf + 2)
    return ""
}

function extractRequestBodyText(request = {}) {
    const rawBody = extractRawBody(request?.raw || "")
    if (rawBody) return rawBody
    if (typeof request?.body === "string") return request.body
    if (request?.body && typeof request.body === "object") {
        try {
            return JSON.stringify(request.body)
        } catch (_) {
            return ""
        }
    }
    return ""
}

function isHtmlLikeResponse(response = {}) {
    const contentType = String(getHeaderValue(response?.headers, "content-type") || response?.mimeType || "").toLowerCase()
    if (contentType.includes("text/html") || contentType.includes("application/xhtml+xml")) return true
    const body = typeof response?.body === "string" ? response.body : ""
    return /^\s*<!doctype html/i.test(body) || /^\s*<html\b/i.test(body)
}

function parseQueryEntries(url, hostHint = null) {
    const raw = toNonEmptyString(url)
    if (!raw) return []
    try {
        const base = hostHint ? `http://${String(hostHint).trim()}` : "http://localhost"
        const parsed = new URL(raw, base)
        const out = []
        for (const [name, value] of parsed.searchParams.entries()) {
            const key = toNonEmptyString(name)
            if (!key) continue
            out.push({ name: key, value: String(value || ""), location: "query" })
        }
        return out
    } catch (_) {
        return []
    }
}

function parseFormEntries(body = "") {
    if (typeof body !== "string" || !body.length) return []
    try {
        const params = new URLSearchParams(body)
        const out = []
        for (const [name, value] of params.entries()) {
            const key = toNonEmptyString(name)
            if (!key) continue
            out.push({ name: key, value: String(value || ""), location: "form" })
        }
        return out
    } catch (_) {
        return []
    }
}

function collectJsonStringLeaves(value, prefix = "", depth = 0, out = [], budget = { count: 0 }) {
    if (budget.count >= 40 || depth > 4 || value === undefined || value === null) return out
    if (typeof value === "string") {
        budget.count += 1
        out.push({
            name: prefix || "<root>",
            value,
            location: "json"
        })
        return out
    }
    if (Array.isArray(value)) {
        value.slice(0, 8).forEach((entry) => {
            collectJsonStringLeaves(entry, prefix ? `${prefix}[]` : "[]", depth + 1, out, budget)
        })
        return out
    }
    if (typeof value === "object") {
        Object.keys(value).slice(0, 20).forEach((key) => {
            const next = prefix ? `${prefix}.${key}` : key
            collectJsonStringLeaves(value[key], next, depth + 1, out, budget)
        })
    }
    return out
}

function parseJsonEntries(request = {}, body = "") {
    const objectBody = request?.body && typeof request.body === "object" ? request.body : null
    if (objectBody && !Array.isArray(objectBody)) {
        return collectJsonStringLeaves(objectBody)
    }
    if (typeof body !== "string" || !body.length) return []
    try {
        const parsed = JSON.parse(body)
        if (!parsed || typeof parsed !== "object") return []
        return collectJsonStringLeaves(parsed)
    } catch (_) {
        return []
    }
}

function parseMultipartEntries(body = "", contentType = "") {
    if (typeof body !== "string" || !body.length) return []
    const boundaryMatch = String(contentType || "").match(/boundary=([^;]+)/i)
    if (!boundaryMatch?.[1]) return []
    const boundary = boundaryMatch[1].trim().replace(/^"|"$/g, "")
    if (!boundary) return []
    const parts = body.split(`--${boundary}`).slice(0, 30)
    const out = []
    parts.forEach((part) => {
        if (!part || part === "--" || /^\s*$/.test(part)) return
        const trimmed = part.replace(/^\r?\n/, "").replace(/\r?\n$/, "")
        const headerEnd = trimmed.indexOf("\r\n\r\n") >= 0
            ? trimmed.indexOf("\r\n\r\n")
            : trimmed.indexOf("\n\n")
        if (headerEnd < 0) return
        const headerBlob = trimmed.slice(0, headerEnd)
        const value = trimmed.slice(headerEnd + (trimmed.includes("\r\n\r\n") ? 4 : 2)).replace(/\r?\n$/, "")
        const dispositionLine = headerBlob
            .split(/\r?\n/)
            .find((line) => /content-disposition:/i.test(line))
        if (!dispositionLine) return
        const nameMatch = dispositionLine.match(/name="([^"]+)"/i)
        const filenameMatch = dispositionLine.match(/filename="([^"]*)"/i)
        const name = toNonEmptyString(nameMatch?.[1])
        if (!name) return
        if (filenameMatch && toNonEmptyString(filenameMatch[1])) return
        out.push({
            name,
            value: String(value || ""),
            location: "multipart"
        })
    })
    return out
}

function collectRequestEntries(request = {}, hostHint = null) {
    const headers = Array.isArray(request?.headers) ? request.headers : []
    const contentType = String(getHeaderValue(headers, "content-type") || "").toLowerCase()
    const body = extractRequestBodyText(request)
    const entries = []
    entries.push(...parseQueryEntries(request?.url, hostHint))
    if (body) {
        if (contentType.includes("application/x-www-form-urlencoded")) {
            entries.push(...parseFormEntries(body))
        } else if (contentType.includes("application/json") || body.trim().startsWith("{")) {
            entries.push(...parseJsonEntries(request, body))
        } else if (contentType.includes("multipart/form-data")) {
            entries.push(...parseMultipartEntries(body, contentType))
        }
    }
    return entries
}

function isLikelyStructuredIdentifier(value = "") {
    const raw = String(value || "").trim()
    if (!raw) return true
    if (NUMERIC_RE.test(raw) || BOOLEAN_RE.test(raw) || UUIDISH_RE.test(raw)) return true
    if (/^[a-z0-9_-]{1,8}$/i.test(raw)) return true
    if (/^[A-Za-z0-9+/=_-]{24,}$/.test(raw) && !/\s/.test(raw)) return true
    return false
}

function scoreTextBearingValue(value = "") {
    const raw = String(value || "")
    const trimmed = raw.trim()
    if (!trimmed) return 0
    if (trimmed.length > 4000) return 0
    let score = 0
    if (/\s/.test(trimmed)) score += 3
    if (trimmed.length >= 8) score += 1
    if (trimmed.length >= 24) score += 2
    if (/[<>{}\[\]$%#@()=:;"'`]/.test(trimmed)) score += 2
    if (/[A-Za-z]/.test(trimmed)) score += 1
    if (/[.,!?/\\-]/.test(trimmed)) score += 1
    if (isLikelyStructuredIdentifier(trimmed)) score -= 3
    return score
}

function resolveSameOriginUrl(candidate, baseUrl, hostHint = null) {
    const raw = toNonEmptyString(candidate)
    const base = toNonEmptyString(baseUrl)
    if (!raw || !base) return null
    try {
        const parsedBase = new URL(base, hostHint ? `http://${String(hostHint).trim()}` : undefined)
        const resolved = new URL(raw, parsedBase)
        if (!["http:", "https:"].includes(resolved.protocol)) return null
        if (resolved.origin !== parsedBase.origin) return null
        return resolved.toString()
    } catch (_) {
        return null
    }
}

function pushEvidence(target = [], refs = []) {
    if (!Array.isArray(refs)) return
    refs.forEach((ref) => {
        if (!ref || typeof ref !== "object") return
        if (target.length >= MAX_EVIDENCE_REFS) return
        target.push(ref)
    })
}

function buildEvidenceRefs({ requestId, routeKey, method, attackId = null } = {}) {
    return normalizeEvidenceRefs([
        requestId ? {
            type: "request",
            id: requestId,
            loc: {
                method,
                path: String(routeKey).split("|")[2] || "/"
            }
        } : null,
        attackId ? {
            type: "attack",
            id: attackId,
            loc: {
                method
            }
        } : null
    ], { maxRefs: MAX_EVIDENCE_REFS })
}

function scoreBucket(bucket = {}) {
    return (
        (bucket.textScore || 0) +
        (bucket.directRenderCount * 10) +
        (bucket.saveRenderCount * 14) +
        (bucket.templateErrorCount * 12) +
        (bucket.multipartCount * 4) +
        Math.min(12, bucket.count * 2)
    )
}

export function runRuleTemplateRenderWorkflows(context = {}) {
    const scanResult = context?.scanResult && typeof context.scanResult === "object" ? context.scanResult : {}
    const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []
    const hostHint = toNonEmptyString(scanResult?.host)
    const buckets = new Map()

    requests.forEach((record, reqIdx) => {
        const requestId = toNonEmptyString(record?.id) || `req-${reqIdx + 1}`
        const request = record?.original?.request || {}
        const response = record?.original?.response || {}
        const method = normalizeMethod(request?.method || "GET")
        const url = request?.url || request?.ui_url || null
        if (!url) return
        const routeKey = buildRouteKey({ url, method, host: hostHint })
        const responseText = typeof response?.body === "string" ? response.body.slice(0, 4096) : ""
        const textEntries = collectRequestEntries(request, hostHint)
            .map((entry) => ({
                ...entry,
                textScore: scoreTextBearingValue(entry.value)
            }))
            .filter((entry) => entry.textScore >= 2)
        if (!textEntries.length) return

        const htmlLike = isHtmlLikeResponse(response)
        const locationHeader = getHeaderValue(response?.headers, "location")
        const refererHeader = getHeaderValue(request?.headers, "referer")
        const uiUrl = request?.ui_url || null
        const sameOriginFollowups = [
            resolveSameOriginUrl(locationHeader, url, hostHint),
            resolveSameOriginUrl(refererHeader, url, hostHint),
            resolveSameOriginUrl(uiUrl, url, hostHint)
        ].filter(Boolean)
        const hasSaveRenderWorkflow = ["POST", "PUT", "PATCH"].includes(method)
            && (sameOriginFollowups.length > 0 || htmlLike)
        const hasDirectRenderSurface = htmlLike
        const hasTemplateError = TEMPLATE_ERROR_RE.test(responseText)

        textEntries.forEach((entry) => {
            const paramKey = normalizeParamKey(entry.name, entry.location || "param")
            const bucketKind = hasSaveRenderWorkflow ? "SAVE_RENDER" : "DIRECT_RENDER"
            if (!hasSaveRenderWorkflow && !hasDirectRenderSurface && !hasTemplateError) return
            const key = `${bucketKind}|${routeKey}|${paramKey}`
            if (!buckets.has(key)) {
                if (buckets.size >= MAX_BUCKETS) return
                buckets.set(key, {
                    kind: bucketKind,
                    routeKey,
                    paramKey,
                    count: 0,
                    textScore: 0,
                    directRenderCount: 0,
                    saveRenderCount: 0,
                    multipartCount: 0,
                    templateErrorCount: 0,
                    followupUrls: new Set(),
                    evidenceRefs: []
                })
            }
            const bucket = buckets.get(key)
            bucket.count += 1
            bucket.textScore = Math.max(bucket.textScore, entry.textScore)
            if (hasDirectRenderSurface) bucket.directRenderCount += 1
            if (hasSaveRenderWorkflow) bucket.saveRenderCount += 1
            if (entry.location === "multipart") bucket.multipartCount += 1
            if (hasTemplateError) bucket.templateErrorCount += 1
            sameOriginFollowups.forEach((followup) => bucket.followupUrls.add(followup))
            pushEvidence(bucket.evidenceRefs, buildEvidenceRefs({ requestId, routeKey, method }))
        })
    })

    const ranked = Array.from(buckets.values())
        .filter((bucket) => Array.isArray(bucket.evidenceRefs) && bucket.evidenceRefs.length > 0)
        .sort((a, b) => {
            const scoreDelta = scoreBucket(b) - scoreBucket(a)
            if (scoreDelta !== 0) return scoreDelta
            return `${a.routeKey}|${a.paramKey}|${a.kind}`.localeCompare(`${b.routeKey}|${b.paramKey}|${b.kind}`)
        })
        .slice(0, MAX_CANDIDATES)

    const patterns = []
    const candidateSeeds = []
    ranked.forEach((bucket) => {
        const routeParts = splitRouteKey(bucket.routeKey)
        const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        const followupUrls = Array.from(bucket.followupUrls).slice(0, 3)
        const priority = scoreBucket(bucket)
        const isSaveRender = bucket.kind === "SAVE_RENDER"
        const paramLabel = bucket.paramKey.replace(/^[^:]+:/, "")

        patterns.push({
            ruleCode: "R10_TEMPLATE_RENDER_WORKFLOWS",
            title: isSaveRender
                ? `Save-then-render template surface on ${routeParts.method} ${routeParts.pathTemplate}`
                : `HTML render template surface on ${routeParts.method} ${routeParts.pathTemplate}`,
            type: isSaveRender ? "TEMPLATE_RENDER_WORKFLOW" : "TEMPLATE_RENDER_SURFACE",
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            priority,
            signals: {
                kind: bucket.kind,
                directRenderCount: bucket.directRenderCount,
                saveRenderCount: bucket.saveRenderCount,
                templateErrorCount: bucket.templateErrorCount,
                followupUrls
            },
            evidenceRefs
        })

        const signals = [
            { code: "TEXTUAL_INPUT_SURFACE", value: paramLabel, weight: Math.min(16, 6 + bucket.textScore) }
        ]
        if (bucket.directRenderCount > 0) {
            signals.push({ code: "HTML_RENDER_SURFACE", value: bucket.directRenderCount, weight: 12 })
        }
        if (bucket.saveRenderCount > 0) {
            signals.push({ code: "SAVE_RENDER_WORKFLOW", value: bucket.saveRenderCount, weight: 16 })
        }
        if (bucket.multipartCount > 0) {
            signals.push({ code: "MULTIPART_TEXT_SURFACE", value: bucket.multipartCount, weight: 8 })
        }
        if (bucket.templateErrorCount > 0) {
            signals.push({ code: "TEMPLATE_ERROR_SIGNATURE", value: bucket.templateErrorCount, weight: 15 })
        }

        candidateSeeds.push({
            createdByRule: "R10_TEMPLATE_RENDER_WORKFLOWS",
            type: "RUNTIME_ANOMALY",
            title: isSaveRender
                ? `Template render workflow candidate on ${routeParts.method} ${routeParts.pathTemplate}`
                : `Template render surface candidate on ${routeParts.method} ${routeParts.pathTemplate}`,
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            engineSignals: ["DAST"],
            repeatabilityCount: bucket.count,
            signals,
            evidenceRefs,
            manualSteps: isSaveRender
                ? [
                    "Replay the captured baseline request with the same headers, cookies, and body shape.",
                    `Mutate only the text-bearing field ${paramLabel} with engine-agnostic template payloads.`,
                    "Validate the result on the follow-up render route or returned HTML view, not only on the save response."
                ]
                : [
                    "Replay the captured baseline request with the original headers and response context.",
                    `Mutate only the text-bearing field ${paramLabel} with low-noise template payloads.`,
                    "Compare the rendered HTML response for evaluation, parser errors, or template-object disclosure."
                ]
        })
    })

    return {
        ruleCode: "R10_TEMPLATE_RENDER_WORKFLOWS",
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds
    }
}

export default runRuleTemplateRenderWorkflows
