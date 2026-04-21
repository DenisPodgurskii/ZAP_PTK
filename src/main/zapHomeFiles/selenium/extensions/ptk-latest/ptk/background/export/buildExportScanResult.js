import CryptoES from "../../packages/crypto-es/index.js"
import { scanResultStore } from "../scanResultStore.js"
import { applyScanAnalysis } from "../analysis/scanAnalysisEngine.js"
import { normalizeEngineName } from "../analysis/canonicalize.js"
import { shouldIncludeScanAnalysisInExport } from "../analysis/featureFlags.js"

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

function firstNonEmpty(...values) {
    for (const value of values) {
        if (value === undefined || value === null) continue
        if (typeof value === "string" && value.trim() === "") continue
        return value
    }
    return null
}

const DEFAULT_TRUNCATE_LIMITS = {
    iast: {
        trace: 16 * 1024,
        stack: 16 * 1024,
        frames: 16 * 1024,
        html: 8 * 1024,
        outerHTML: 8 * 1024,
        dom: 8 * 1024,
        message: 4 * 1024,
        matched: 2 * 1024,
        value: 2 * 1024,
        inlineValue: 2 * 1024
    },
    sast: {
        codeSnippet: 8 * 1024,
        flow: 8 * 1024
    },
    dast: {
        proof: 8 * 1024,
        payload: 4 * 1024,
        requestBody: 64 * 1024,
        responseBody: 64 * 1024,
        rawMessage: 64 * 1024
    },
    sca: {
        summary: 8 * 1024
    },
    artifacts: {
        string: 4 * 1024,
        depth: 6
    }
}

const SENSITIVE_HEADER_NAMES = new Set([
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key"
])

const SECRET_KEY_REGEX = /("(?:password|passwd|pwd|token|access_token|api[_-]?key|secret)"\s*:\s*")([^"]{4,})(")/gi
const SECRET_QUERY_REGEX = /((?:\?|&)(?:password|passwd|pwd|token|access_token|api[_-]?key|secret)=)([^&#\s]+)/gi
const SECRET_ASSIGN_REGEX = /((?:password|passwd|pwd|token|access_token|api[_-]?key|secret)\s*[=:]\s*)([^\s,'";]{4,})/gi
const BEARER_REGEX = /(Bearer\s+)([A-Za-z0-9._~+\-/=]{20,})/gi
const JWT_REGEX = /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g
const OPENAI_REGEX = /\bsk-[A-Za-z0-9]{16,}\b/g
const GOOGLE_REGEX = /\bAIza[0-9A-Za-z_\-]{30,}\b/g
const HEX_TOKEN_REGEX = /\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d)[0-9a-f]{40,}\b/gi
const BUG_BOUNTY_SECRET_KEY_REGEX = /(?:^|[_-])(secret|token|password|passwd|pwd|api(?:[_-]?key)?|auth(?:orization)?|bearer|credential|credentials|csrf(?:[_-]?token)?|session(?:[_-]?(?:state|storage|token|id))|storage(?:[_-]?state)?|localstorage|sessionstorage|cookie(?:s)?|setcookie|request(?:[_-]?body)?|response(?:[_-]?body)?|raw(?:[_-]?(?:request|response))?|headers?|body)$/i
const BUG_BOUNTY_SAFE_STRING_LIMIT = 8 * 1024

function cloneValue(value) {
    if (typeof globalThis.structuredClone === "function") {
        try {
            return globalThis.structuredClone(value)
        } catch (_) {
            // fall back to JSON clone
        }
    }
    return JSON.parse(JSON.stringify(value ?? {}))
}

function resolveScanResult(scanId, provided) {
    if (provided) return provided
    if (!scanId) return null
    const scan = scanResultStore.getScan(scanId)
    return scan || null
}

function resolveRelatedScans(scanId, provided, scanResult = null) {
    if (Array.isArray(provided)) return provided
    if (!scanResultStore?.getRelatedScansForAnalysis) return []
    return scanResultStore.getRelatedScansForAnalysis({
        scanId: scanId || scanResult?.scanId || null,
        host: scanResult?.host || null,
        tabId: scanResult?.tabId,
        engine: scanResult?.engine || null
    })
}

function deriveExtraEnginesPresent(relatedScans = []) {
    const engines = new Set()
    ;(Array.isArray(relatedScans) ? relatedScans : []).forEach((scan) => {
        const engine = normalizeEngineName(scan?.engine)
        if (engine) engines.add(engine)
    })
    return Array.from(engines)
}

function maskSecret(value) {
    if (!value || typeof value !== "string") return "[REDACTED]"
    if (value.length <= 10) return "[REDACTED]"
    return `${value.slice(0, 6)}...${value.slice(-4)}`
}

export function redactSensitiveStrings(input) {
    if (typeof input !== "string") return input
    let value = input
    value = value.replace(SECRET_KEY_REGEX, (_, prefix, secret, suffix) => `${prefix}${maskSecret(secret)}${suffix}`)
    value = value.replace(SECRET_QUERY_REGEX, (_, prefix, secret) => `${prefix}${maskSecret(secret)}`)
    value = value.replace(SECRET_ASSIGN_REGEX, (_, prefix, secret) => `${prefix}${maskSecret(secret)}`)
    value = value.replace(BEARER_REGEX, (_, prefix, token) => `${prefix}${maskSecret(token)}`)
    value = value.replace(JWT_REGEX, match => maskSecret(match))
    value = value.replace(OPENAI_REGEX, match => maskSecret(match))
    value = value.replace(GOOGLE_REGEX, match => maskSecret(match))
    value = value.replace(HEX_TOKEN_REGEX, match => maskSecret(match))
    return value
}

function sanitizeHeaderEntries(headers) {
    if (!headers) return headers
    if (Array.isArray(headers)) {
        return headers.map(entry => {
            if (!entry || typeof entry !== "object") return entry
            const name = String(entry.name || entry.key || "").toLowerCase()
            const clone = { ...entry }
            if (clone.value !== undefined) {
                clone.value = SENSITIVE_HEADER_NAMES.has(name)
                    ? "[REDACTED]"
                    : redactSensitiveStrings(String(clone.value))
            }
            return clone
        })
    }
    if (typeof headers === "object") {
        const clone = { ...headers }
        Object.keys(clone).forEach((key) => {
            const lower = String(key).toLowerCase()
            const value = clone[key]
            if (value === undefined || value === null) return
            if (SENSITIVE_HEADER_NAMES.has(lower)) {
                clone[key] = "[REDACTED]"
            } else if (typeof value === "string") {
                clone[key] = redactSensitiveStrings(value)
            }
        })
        return clone
    }
    return headers
}

function sanitizeObjectStrings(value, depth = 3) {
    if (!value || depth <= 0) return value
    if (Array.isArray(value)) {
        return value.map(entry => sanitizeObjectStrings(entry, depth - 1))
    }
    if (typeof value === "object") {
        const clone = { ...value }
        Object.keys(clone).forEach((key) => {
            const val = clone[key]
            if (typeof val === "string") {
                clone[key] = redactSensitiveStrings(val)
            } else if (val && typeof val === "object") {
                clone[key] = sanitizeObjectStrings(val, depth - 1)
            }
        })
        return clone
    }
    return value
}

function sanitizeScanConfiguration(settings) {
    const cloned = (settings && typeof settings === "object") ? cloneValue(settings) : {}
    if (!cloned || typeof cloned !== "object") return {}
    delete cloned.rulepack
    delete cloned.cveRulepack
    delete cloned.onResultMutation
    return sanitizeObjectStrings(cloned, 6) || {}
}

function sanitizeBodyObject(body, limits, labelPrefix) {
    if (!body || typeof body !== "object") return
    if (typeof body.text === "string") {
        body.text = sanitizeString(body.text, limits.bodyLimit, `${labelPrefix}.body.text`)
    }
    if (Array.isArray(body.params)) {
        body.params = body.params.map((param) => {
            if (!param || typeof param !== "object") return param
            const clone = { ...param }
            if (typeof clone.value === "string") {
                clone.value = redactSensitiveStrings(clone.value)
            }
            return clone
        })
    }
    if (body.json && typeof body.json === "object") {
        body.json = sanitizeObjectStrings(body.json)
    }
}

function sanitizeHttpMessage(message, { bodyLimit, rawLimit, labelPrefix }) {
    if (!message || typeof message !== "object") return
    if (typeof message.url === "string") {
        message.url = redactSensitiveStrings(message.url)
    }
    if (typeof message.ui_url === "string") {
        message.ui_url = redactSensitiveStrings(message.ui_url)
    }
    if (message.headers) {
        message.headers = sanitizeHeaderEntries(message.headers)
    }
    if (typeof message.raw === "string") {
        message.raw = sanitizeString(message.raw, rawLimit, `${labelPrefix}.raw`)
    }
    if (typeof message.body === "string") {
        message.body = sanitizeString(message.body, bodyLimit, `${labelPrefix}.body`)
    } else if (message.body && typeof message.body === "object") {
        sanitizeBodyObject(message.body, { bodyLimit }, labelPrefix)
    }
    if (typeof message.statusLine === "string") {
        message.statusLine = sanitizeString(message.statusLine, 512, `${labelPrefix}.statusLine`)
    }
    if (Array.isArray(message.cookies)) {
        message.cookies = message.cookies.map((cookie) => {
            if (!cookie || typeof cookie !== "object") return cookie
            const name = String(cookie.name || "").toLowerCase()
            const clone = { ...cookie }
            if (clone.value && (name.includes("token") || name.includes("auth") || name.includes("session"))) {
                clone.value = "[REDACTED]"
            } else if (typeof clone.value === "string") {
                clone.value = redactSensitiveStrings(clone.value)
            }
            return clone
        })
    }
}

function parseRuntimeUrl(rawUrl) {
    if (!rawUrl) return null
    try {
        const url = new URL(rawUrl, rawUrl.startsWith("http") ? undefined : "http://placeholder")
        const hashValue = url.hash ? url.hash.slice(1) : ""
        const [hashPathRaw, hashQueryRaw] = hashValue.split("?")
        const origin = url.origin === "http://placeholder" ? "" : url.origin
        return {
            origin,
            pathname: url.pathname || "",
            search: url.search || "",
            hashPathRaw: hashPathRaw || "",
            hashQueryRaw: hashQueryRaw || ""
        }
    } catch (_) {
        return null
    }
}

function buildUrlPattern(rawUrl, parts) {
    if (!rawUrl || !parts) return null
    const searchParams = new URLSearchParams(parts.search || "")
    const hashParams = new URLSearchParams(parts.hashQueryRaw || "")
    for (const key of searchParams.keys()) {
        searchParams.set(key, "*")
    }
    for (const key of hashParams.keys()) {
        hashParams.set(key, "*")
    }
    const search = searchParams.toString()
    const hashQuery = hashParams.toString()
    const base = `${parts.origin}${parts.pathname}`
    let pattern = base || rawUrl
    if (search) {
        pattern += `?${search}`
    }
    if (parts.hashPathRaw || hashQuery) {
        pattern += `#${parts.hashPathRaw || ""}`
        if (hashQuery) {
            pattern += `?${hashQuery}`
        }
    }
    return pattern
}

function deriveSourceMetaFromFinding(finding) {
    const sourcePath = finding?.evidence?.sast?.source?.path
    if (!sourcePath || typeof sourcePath !== "string") return null
    const trimmed = sourcePath.trim()
    if (!trimmed) return null
    const lowered = trimmed.toLowerCase()
    let kind = null
    if (lowered.includes("queryparams") || lowered.includes("queryparam") || lowered.includes("searchparams")) {
        kind = "query"
    }
    if (!kind) return null
    const segments = trimmed.split(".").filter(Boolean)
    const name = segments.length ? segments[segments.length - 1] : null
    if (!name) return null
    return { kind, name, path: trimmed }
}

function extractQueryKeysFromUrl(rawUrl) {
    const parts = parseRuntimeUrl(rawUrl)
    if (!parts) return []
    const keys = []
    const seen = new Set()
    const addKey = (key) => {
        const value = key && String(key).trim()
        if (!value || seen.has(value)) return
        seen.add(value)
        keys.push(value)
    }
    const searchParams = new URLSearchParams(parts.search || "")
    for (const key of searchParams.keys()) addKey(key)
    const hashParams = new URLSearchParams(parts.hashQueryRaw || "")
    for (const key of hashParams.keys()) addKey(key)
    return keys
}

function pickSafeParamName(queryKeys, candidate) {
    if (candidate && typeof candidate === "string") {
        const trimmed = candidate.trim()
        if (trimmed && queryKeys.includes(trimmed)) return trimmed
    }
    if (queryKeys.length === 1) return queryKeys[0]
    return null
}

function gatherIastUrls(finding) {
    const urls = []
    const evidence = finding?.evidence?.iast || {}
    const pushUrl = (value) => {
        if (!value || typeof value !== "string") return
        if (!/^https?:\/\//i.test(value)) return
        urls.push(value)
    }
    if (evidence.context?.url) pushUrl(evidence.context.url)
    if (Array.isArray(evidence.affectedUrls)) {
        evidence.affectedUrls.forEach(pushUrl)
    }
    if (Array.isArray(evidence.sources)) {
        evidence.sources.forEach(entry => {
            if (!entry || typeof entry !== "object") return
            if (entry.location) pushUrl(entry.location)
        })
    }
    return urls
}

function deriveFallbackParam(finding, loc) {
    if (!finding || !loc) return null
    const engine = String(finding.engine || "").toUpperCase()
    const runtimeUrl = loc.runtimeUrl || loc.url || loc.pageUrl || null
    const queryKeys = extractQueryKeysFromUrl(runtimeUrl || "")
    if (engine === "DAST") {
        const candidate = firstNonEmpty(
            finding?.evidence?.dast?.param,
            finding?.evidence?.dast?.attack?.param,
            finding?.evidence?.dast?.attack?.meta?.attacked?.name
        )
        return pickSafeParamName(queryKeys, candidate)
    }
    if (engine === "IAST") {
        const candidate = firstNonEmpty(
            finding?.evidence?.iast?.param,
            finding?.evidence?.iast?.source?.name,
            finding?.evidence?.iast?.source?.label
        )
        let param = pickSafeParamName(queryKeys, candidate)
        if (param) return param
        const urls = gatherIastUrls(finding)
        for (const url of urls) {
            const keys = extractQueryKeysFromUrl(url)
            param = pickSafeParamName(keys, candidate)
            if (param) return param
        }
    }
    return null
}

function enrichFindingLocation(finding) {
    if (!finding || typeof finding !== "object") return
    if (!finding.location || typeof finding.location !== "object") {
        finding.location = {}
    }
    const loc = finding.location
    const runtimeUrl = loc.runtimeUrl || loc.url || loc.pageUrl || finding.pageUrl || finding.pageCanon || null
    if (runtimeUrl) {
        loc.runtimeUrl = runtimeUrl
    }
    const parts = parseRuntimeUrl(runtimeUrl)
    if (!parts) return
    const route = parts.hashPathRaw ? `#${parts.hashPathRaw}` : (parts.pathname || null)
    if (route) {
        loc.route = loc.route || route
    }
    const queryKeys = []
    const seen = new Set()
    const addKey = (key) => {
        const value = key && String(key).trim()
        if (!value || seen.has(value)) return
        seen.add(value)
        queryKeys.push(value)
    }
    const searchParams = new URLSearchParams(parts.search || "")
    for (const key of searchParams.keys()) addKey(key)
    const hashParams = new URLSearchParams(parts.hashQueryRaw || "")
    for (const key of hashParams.keys()) addKey(key)
    if (queryKeys.length) {
        loc.queryKeys = Array.isArray(loc.queryKeys) && loc.queryKeys.length ? loc.queryKeys : queryKeys
        if (!loc.param && queryKeys.length === 1) {
            loc.param = queryKeys[0]
        }
    }
    if (!loc.param) {
        const fallbackParam = deriveFallbackParam(finding, loc)
        if (fallbackParam) loc.param = fallbackParam
    }
    const urlPattern = buildUrlPattern(runtimeUrl, parts)
    if (urlPattern) {
        loc.urlPattern = loc.urlPattern || urlPattern
    }
}

function enrichFindingSource(finding) {
    if (!finding || typeof finding !== "object") return
    if (finding.source && typeof finding.source === "object") return
    const sourceMeta = deriveSourceMetaFromFinding(finding)
    if (!sourceMeta) return
    finding.source = sourceMeta
    if (sourceMeta.name) {
        if (!finding.location || typeof finding.location !== "object") {
            finding.location = {}
        }
        if (!finding.location.param) {
            finding.location.param = sourceMeta.name
        }
    }
}

function buildCorrelationKey(finding) {
    if (!finding || typeof finding !== "object") return null
    const loc = finding.location || {}
    const route = loc.route || ""
    const queryKeys = Array.isArray(loc.queryKeys) ? loc.queryKeys.join(",") : ""
    const sinkId = finding?.evidence?.iast?.sinkId
        || finding?.evidence?.dast?.attackId
        || finding?.evidence?.sast?.sinkId
        || finding.sinkId
        || ""
    const payload = [
        finding.vulnId || "",
        route,
        queryKeys,
        sinkId,
        finding.ruleId || "",
        finding.moduleId || ""
    ].join("|")
    if (!payload.replace(/\|/g, "").trim()) return null
    return CryptoES.SHA256(payload).toString(CryptoES.enc.Hex)
}

function enrichFindingsForExport(findings = []) {
    if (!Array.isArray(findings)) return
    findings.forEach(finding => {
        if (!finding || typeof finding !== "object") return
        enrichFindingLocation(finding)
        enrichFindingSource(finding)
        if (!finding.correlationKey) {
            const key = buildCorrelationKey(finding)
            if (key) finding.correlationKey = key
        }
    })
}

function normalizePageUrl(rawUrl) {
    if (!rawUrl) return null
    try {
        return new URL(rawUrl, rawUrl.startsWith("http") ? undefined : "http://placeholder").toString()
    } catch (_) {
        return String(rawUrl)
    }
}

function normalizeRequestKey(url, method) {
    if (!url) return null
    try {
        const parsed = new URL(url, url.startsWith("http") ? undefined : "http://placeholder")
        const base = `${parsed.origin}${parsed.pathname}${parsed.search || ""}`
        return `${(method || "GET").toUpperCase()} ${base}`
    } catch (_) {
        return `${(method || "GET").toUpperCase()} ${url}`
    }
}

function buildRequestMetaMap(requests = []) {
    if (!Array.isArray(requests)) return new Map()
    const map = new Map()
    requests.forEach(entry => {
        const original = entry?.original || {}
        const req = original.request || {}
        const url = normalizePageUrl(req.ui_url || req.url || null)
        if (!url) return
        const key = normalizeRequestKey(req.url || req.ui_url || url, req.method)
        const meta = {
            method: req.method || null,
            status: original?.response?.statusCode || original?.response?.status || null,
            mimeType: original?.response?.mimeType || null
        }
        map.set(url, { requestKey: key, requestMeta: meta })
    })
    return map
}

function buildPageStats(url, findings = []) {
    const stats = {
        totalFindings: 0,
        byCategory: {},
        bySeverity: {}
    }
    const findingIds = []
    findings.forEach(finding => {
        const loc = finding?.location || {}
        const runtimeUrl = loc.runtimeUrl || loc.url || loc.pageUrl || null
        if (!runtimeUrl || runtimeUrl !== url) return
        stats.totalFindings += 1
        const category = String(finding.category || "other").toLowerCase()
        stats.byCategory[category] = (stats.byCategory[category] || 0) + 1
        const severity = String(finding.severity || "info").toLowerCase()
        stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1
        if (finding.id) findingIds.push(finding.id)
    })
    return { stats, findingIds }
}

function derivePagesForExport(scanResult) {
    if (!scanResult || typeof scanResult !== "object") return
    const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
    const requestMetaMap = buildRequestMetaMap(scanResult.requests)
    const urls = new Set()
    const existing = Array.isArray(scanResult.pages) ? scanResult.pages : []
    existing.forEach(entry => {
        const url = typeof entry === "string" ? entry : entry?.url
        const normalized = normalizePageUrl(url)
        if (normalized) urls.add(normalized)
    })
    findings.forEach(finding => {
        const loc = finding?.location || {}
        const runtimeUrl = loc.runtimeUrl || loc.url || loc.pageUrl || null
        const normalized = normalizePageUrl(runtimeUrl)
        if (normalized) urls.add(normalized)
    })
    if (!urls.size) return
    const pages = []
    urls.forEach(url => {
        const { stats, findingIds } = buildPageStats(url, findings)
        const requestInfo = requestMetaMap.get(url) || null
        const pageEntry = {
            url,
            stats,
            findingIds
        }
        if (requestInfo?.requestKey) pageEntry.requestKey = requestInfo.requestKey
        if (requestInfo?.requestMeta) pageEntry.requestMeta = requestInfo.requestMeta
        pages.push(pageEntry)
    })
    scanResult.pages = pages
}

function enrichGroupsForExport(scanResult) {
    if (!scanResult || typeof scanResult !== "object") return
    const groups = Array.isArray(scanResult.groups) ? scanResult.groups : []
    const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
    const byId = new Map()
    findings.forEach(finding => {
        if (finding?.id) byId.set(finding.id, finding)
    })
    groups.forEach(group => {
        if (!group || typeof group !== "object") return
        const occurrenceIds = Array.isArray(group.occurrenceIds) ? group.occurrenceIds : []
        let found = null
        for (const id of occurrenceIds) {
            if (byId.has(id)) {
                found = byId.get(id)
                break
            }
        }
        if (!found) return
        if (!group.location || typeof group.location !== "object") {
            group.location = {}
        }
        const loc = found.location || {}
        const runtimeUrl = loc.runtimeUrl || loc.url || loc.pageUrl || null
        if (runtimeUrl) {
            if (!group.location.runtimeUrl) group.location.runtimeUrl = runtimeUrl
            if (!group.location.url) group.location.url = runtimeUrl
        }
        if (!group.correlationKey && found.correlationKey) {
            group.correlationKey = found.correlationKey
        }
    })
}

function trimBytesToBoundary(bytes, limit) {
    if (bytes.length <= limit) {
        return bytes
    }
    let end = limit
    while (end > 0 && (bytes[end] & 0b11000000) === 0b10000000) {
        end -= 1
    }
    if (end <= 0) {
        return bytes.slice(0, limit)
    }
    return bytes.slice(0, end)
}

export function truncateAndMarkString(value, maxBytes = 0, label = null) {
    if (typeof value !== "string") return value
    const redacted = redactSensitiveStrings(value)
    if (!maxBytes || maxBytes <= 0) {
        return redacted
    }
    const encoded = textEncoder.encode(redacted)
    if (encoded.length <= maxBytes) {
        return redacted
    }
    const sliced = trimBytesToBoundary(encoded, maxBytes)
    const preview = textDecoder.decode(sliced)
    return {
        __type: "truncated_string",
        preview,
        truncated: true,
        originalLength: encoded.length,
        sha256: CryptoES.SHA256(redacted).toString(CryptoES.enc.Hex),
        label: label || null
    }
}

function sanitizeString(value, maxBytes, label) {
    if (typeof value === "string") {
        return truncateAndMarkString(value, maxBytes, label)
    }
    return value
}

function sanitizeArrayStrings(arr, maxBytes, label) {
    if (!Array.isArray(arr)) return arr
    return arr.map(entry => {
        if (typeof entry === "string") {
            return truncateAndMarkString(entry, maxBytes, label)
        }
        if (entry && typeof entry === "object") {
            const clone = { ...entry }
            Object.keys(clone).forEach(key => {
                if (typeof clone[key] === "string") {
                    clone[key] = truncateAndMarkString(clone[key], maxBytes, label ? `${label}.${key}` : null)
                }
            })
            return clone
        }
        return entry
    })
}

function sanitizeIastEvidence(evidence = {}) {
    if (!evidence || typeof evidence !== "object") return
    const limits = DEFAULT_TRUNCATE_LIMITS.iast
    if (typeof evidence.trace === "string" || Array.isArray(evidence.trace)) {
        evidence.trace = sanitizeArrayStrings([evidence.trace].flat(), limits.trace, "iast.trace")
        if (Array.isArray(evidence.trace) && evidence.trace.length === 1) {
            evidence.trace = evidence.trace[0]
        }
    }
    if (typeof evidence.stack === "string") {
        evidence.stack = sanitizeString(evidence.stack, limits.stack, "iast.stack")
    }
    if (Array.isArray(evidence.frames)) {
        evidence.frames = sanitizeArrayStrings(evidence.frames, limits.frames, "iast.frames")
    }
    if (typeof evidence.message === "string") {
        evidence.message = sanitizeString(evidence.message, limits.message, "iast.message")
    }
    if (typeof evidence.matched === "string") {
        evidence.matched = sanitizeString(evidence.matched, limits.matched, "iast.matched")
    }
    if (typeof evidence.value === "string") {
        evidence.value = sanitizeString(evidence.value, limits.value, "iast.value")
    }
    if (typeof evidence.inlineValue === "string") {
        evidence.inlineValue = sanitizeString(evidence.inlineValue, limits.inlineValue, "iast.inlineValue")
    }
    if (typeof evidence.source === "string") {
        evidence.source = redactSensitiveStrings(evidence.source)
    }
    if (typeof evidence.sink === "string") {
        evidence.sink = redactSensitiveStrings(evidence.sink)
    }
    if (Array.isArray(evidence.sources)) {
        evidence.sources = evidence.sources.map((src) => {
            if (!src || typeof src !== "object") return src
            const clone = { ...src }
            if (typeof clone.value === "string") {
                clone.value = sanitizeString(clone.value, limits.value, "iast.source.value")
            }
            if (typeof clone.raw === "string") {
                clone.raw = sanitizeString(clone.raw, limits.value, "iast.source.raw")
            }
            if (typeof clone.display === "string") {
                clone.display = sanitizeString(clone.display, limits.value, "iast.source.display")
            }
            if (typeof clone.key === "string") {
                clone.key = redactSensitiveStrings(clone.key)
            }
            if (typeof clone.source === "string") {
                clone.source = redactSensitiveStrings(clone.source)
            }
            return clone
        })
    }
    if (Array.isArray(evidence.affectedUrls)) {
        evidence.affectedUrls = evidence.affectedUrls.map(entry => {
            if (typeof entry !== "string") return entry
            return redactSensitiveStrings(entry)
        })
    }
    if (evidence.context && typeof evidence.context === "object") {
        const ctx = evidence.context
        if (typeof ctx.elementOuterHTML === "string") {
            ctx.elementOuterHTML = sanitizeString(ctx.elementOuterHTML, limits.outerHTML, "iast.context.elementOuterHTML")
        }
        if (typeof ctx.outerHTML === "string") {
            ctx.outerHTML = sanitizeString(ctx.outerHTML, limits.outerHTML, "iast.context.outerHTML")
        }
        if (typeof ctx.html === "string") {
            ctx.html = sanitizeString(ctx.html, limits.html, "iast.context.html")
        }
        if (typeof ctx.domPath === "string") {
            ctx.domPath = sanitizeString(ctx.domPath, limits.dom, "iast.context.domPath")
        }
        if (typeof ctx.value === "string") {
            ctx.value = sanitizeString(ctx.value, limits.value, "iast.context.value")
        }
        if (typeof ctx.valuePreview === "string") {
            ctx.valuePreview = sanitizeString(ctx.valuePreview, limits.value, "iast.context.valuePreview")
        }
        if (typeof ctx.url === "string") {
            ctx.url = redactSensitiveStrings(ctx.url)
        }
    }
}

function sanitizeSastEvidence(evidence = {}) {
    if (!evidence || typeof evidence !== "object") return
    const limits = DEFAULT_TRUNCATE_LIMITS.sast
    if (typeof evidence.codeSnippet === "string") {
        evidence.codeSnippet = sanitizeString(evidence.codeSnippet, limits.codeSnippet, "sast.codeSnippet")
    }
    if (Array.isArray(evidence.flow)) {
        evidence.flow = sanitizeArrayStrings(evidence.flow, limits.flow, "sast.flow")
    }
    if (Array.isArray(evidence.trace)) {
        evidence.trace = evidence.trace.map((step) => {
            if (!step || typeof step !== "object") return step
            return sanitizeObjectStrings(step, 3)
        })
    } else if (evidence.trace && typeof evidence.trace === "object") {
        evidence.trace = sanitizeObjectStrings(evidence.trace, 3)
    }
    if (evidence.source && typeof evidence.source === "object") {
        evidence.source = sanitizeObjectStrings(evidence.source, 3)
    }
    if (evidence.sink && typeof evidence.sink === "object") {
        evidence.sink = sanitizeObjectStrings(evidence.sink, 3)
    }
}

function sanitizeDastEvidence(evidence = {}) {
    if (!evidence || typeof evidence !== "object") return
    const limits = DEFAULT_TRUNCATE_LIMITS.dast
    if (typeof evidence.proof === "string") {
        evidence.proof = sanitizeString(evidence.proof, limits.proof, "dast.proof")
    }
    if (typeof evidence.payload === "string") {
        evidence.payload = sanitizeString(evidence.payload, limits.payload, "dast.payload")
    }
    if (typeof evidence.param === "string") {
        evidence.param = redactSensitiveStrings(evidence.param)
    }
    if (typeof evidence.attack?.payload === "string") {
        evidence.attack.payload = sanitizeString(evidence.attack.payload, limits.payload, "dast.attack.payload")
    }
    if (typeof evidence.attack?.proof === "string") {
        evidence.attack.proof = sanitizeString(evidence.attack.proof, limits.proof, "dast.attack.proof")
    }
    if (evidence.attack?.meta) {
        evidence.attack.meta = sanitizeObjectStrings(evidence.attack.meta, 3)
    }
    sanitizeHttpMessage(evidence.request, {
        bodyLimit: limits.requestBody,
        rawLimit: limits.rawMessage,
        labelPrefix: "dast.request"
    })
    sanitizeHttpMessage(evidence.response, {
        bodyLimit: limits.responseBody,
        rawLimit: limits.rawMessage,
        labelPrefix: "dast.response"
    })
    sanitizeHttpMessage(evidence.attack?.request, {
        bodyLimit: limits.requestBody,
        rawLimit: limits.rawMessage,
        labelPrefix: "dast.attack.request"
    })
    sanitizeHttpMessage(evidence.attack?.response, {
        bodyLimit: limits.responseBody,
        rawLimit: limits.rawMessage,
        labelPrefix: "dast.attack.response"
    })
    sanitizeHttpMessage(evidence.original?.request, {
        bodyLimit: limits.requestBody,
        rawLimit: limits.rawMessage,
        labelPrefix: "dast.original.request"
    })
    sanitizeHttpMessage(evidence.original?.response, {
        bodyLimit: limits.responseBody,
        rawLimit: limits.rawMessage,
        labelPrefix: "dast.original.response"
    })
    // Enforce refs-only evidence for DAST to avoid duplicating full HTTP payloads.
    if (Object.prototype.hasOwnProperty.call(evidence, "request")) delete evidence.request
    if (Object.prototype.hasOwnProperty.call(evidence, "response")) delete evidence.response
    if (Object.prototype.hasOwnProperty.call(evidence, "original")) delete evidence.original
    if (evidence.attack && typeof evidence.attack === "object") {
        if (Object.prototype.hasOwnProperty.call(evidence.attack, "request")) delete evidence.attack.request
        if (Object.prototype.hasOwnProperty.call(evidence.attack, "response")) delete evidence.attack.response
    }
}

function sanitizeScaEvidence(evidence = {}) {
    if (!evidence || typeof evidence !== "object") return
    const limits = DEFAULT_TRUNCATE_LIMITS.sca
    if (typeof evidence.summary === "string") {
        evidence.summary = sanitizeString(evidence.summary, limits.summary, "sca.summary")
    }
    if (evidence.component && typeof evidence.component === "object") {
        evidence.component = sanitizeObjectStrings(evidence.component, 4)
    }
    if (evidence.identifiers && typeof evidence.identifiers === "object") {
        evidence.identifiers = sanitizeObjectStrings(evidence.identifiers, 4)
    }
    if (evidence.versionRange && typeof evidence.versionRange === "object") {
        evidence.versionRange = sanitizeObjectStrings(evidence.versionRange, 3)
    }
    if (Array.isArray(evidence.info)) {
        evidence.info = evidence.info.map(entry => {
            if (typeof entry !== "string") return entry
            return redactSensitiveStrings(entry)
        })
    }
    if (typeof evidence.sourceFile === "string") {
        evidence.sourceFile = redactSensitiveStrings(evidence.sourceFile)
    }
}

function sanitizeArtifactValue(value, { maxBytes, depth, label }) {
    if (value === null || value === undefined) return value
    if (typeof value === "string") {
        return sanitizeString(value, maxBytes, label)
    }
    if (Array.isArray(value)) {
        if (depth <= 0) return value
        return value.map((entry, index) => sanitizeArtifactValue(entry, {
            maxBytes,
            depth: depth - 1,
            label: label ? `${label}[${index}]` : null
        }))
    }
    if (typeof value === "object") {
        if (depth <= 0) return value
        const clone = { ...value }
        Object.keys(clone).forEach((key) => {
            clone[key] = sanitizeArtifactValue(clone[key], {
                maxBytes,
                depth: depth - 1,
                label: label ? `${label}.${key}` : key
            })
        })
        return clone
    }
    return value
}

function sanitizeCodeArtifacts(codeArtifacts) {
    if (!codeArtifacts || typeof codeArtifacts !== "object") return
    const limits = DEFAULT_TRUNCATE_LIMITS.artifacts
    Object.keys(codeArtifacts).forEach((key) => {
        codeArtifacts[key] = sanitizeArtifactValue(codeArtifacts[key], {
            maxBytes: limits.string,
            depth: limits.depth,
            label: `artifacts.${key}`
        })
    })
}

function shouldIncludeBugBountyData(opts = {}) {
    return opts?.includeBugBountyData === true || opts?.includeBugBounty === true
}

function isBugBountySecretKey(key) {
    if (!key) return false
    const raw = String(key)
    const normalized = raw
        .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
        .replace(/[\s.]+/g, "_")
    return BUG_BOUNTY_SECRET_KEY_REGEX.test(raw) || BUG_BOUNTY_SECRET_KEY_REGEX.test(normalized)
}

function sanitizeBugBountyValue(value, label = "bugbounty", depth = 8) {
    if (value === null || value === undefined) return value
    if (typeof value === "string") {
        return sanitizeString(redactSensitiveStrings(value), BUG_BOUNTY_SAFE_STRING_LIMIT, label)
    }
    if (Array.isArray(value)) {
        if (depth <= 0) return value
        return value.map((entry, index) => sanitizeBugBountyValue(entry, `${label}[${index}]`, depth - 1))
    }
    if (typeof value === "object") {
        if (depth <= 0) return value
        const clone = {}
        Object.keys(value).forEach((key) => {
            if (isBugBountySecretKey(key)) return
            clone[key] = sanitizeBugBountyValue(value[key], label ? `${label}.${key}` : key, depth - 1)
        })
        return clone
    }
    return value
}

function sanitizeBugBountyPayload(bugBounty, opts = {}) {
    if (!bugBounty || typeof bugBounty !== "object") return bugBounty
    const clone = cloneValue(bugBounty)
    return sanitizeBugBountyValue(clone, "bugbounty")
}

function sanitizeRequests(requests = []) {
    if (!Array.isArray(requests)) return
    const limits = DEFAULT_TRUNCATE_LIMITS.dast
    requests.forEach(record => {
        if (!record || typeof record !== "object") return
        sanitizeHttpMessage(record?.original?.request, {
            bodyLimit: limits.requestBody,
            rawLimit: limits.rawMessage,
            labelPrefix: "dast.requests.original.request"
        })
        sanitizeHttpMessage(record?.original?.response, {
            bodyLimit: limits.responseBody,
            rawLimit: limits.rawMessage,
            labelPrefix: "dast.requests.original.response"
        })
        const attacks = Array.isArray(record.attacks) ? record.attacks : []
        attacks.forEach((attack, idx) => {
            sanitizeHttpMessage(attack?.request, {
                bodyLimit: limits.requestBody,
                rawLimit: limits.rawMessage,
                labelPrefix: `dast.requests.attacks[${idx}].request`
            })
            sanitizeHttpMessage(attack?.response, {
                bodyLimit: limits.responseBody,
                rawLimit: limits.rawMessage,
                labelPrefix: `dast.requests.attacks[${idx}].response`
            })
        })
    })
}

function sanitizeHeader(header) {
    if (!header || typeof header !== "object") return header
    const name = typeof header.name === "string" ? header.name : header.key
    if (typeof name === "string") {
        const lower = name.toLowerCase()
        if (SENSITIVE_HEADER_NAMES.has(lower)) {
            return { ...header, value: maskSecret(header.value || "") }
        }
    }
    if (typeof header.value === "string") {
        return { ...header, value: redactSensitiveStrings(header.value) }
    }
    return header
}

function sanitizeFinding(finding) {
    if (!finding || typeof finding !== "object") return
    const engine = (finding.engine || "").toUpperCase()
    const evidence = finding.evidence || {}
    if (engine === "IAST" && evidence.iast) {
        sanitizeIastEvidence(evidence.iast)
    } else if (engine === "SAST" && evidence.sast) {
        sanitizeSastEvidence(evidence.sast)
    } else if (engine === "DAST" && evidence.dast) {
        sanitizeDastEvidence(evidence.dast)
    } else if (engine === "SCA" && evidence.sca) {
        sanitizeScaEvidence(evidence.sca)
    }
}

function rebuildStats(findings = []) {
    const stats = { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    findings.forEach(finding => {
        if (!finding) return
        stats.findingsCount += 1
        const severity = String(finding.severity || "info").toLowerCase()
        if (stats.hasOwnProperty(severity)) {
            stats[severity] = (stats[severity] || 0) + 1
        } else {
            stats.info = (stats.info || 0) + 1
        }
    })
    return stats
}

export function sanitizeScanResult(scanResult, opts = {}) {
    if (!scanResult || typeof scanResult !== "object") return scanResult
    const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
    findings.forEach(sanitizeFinding)
    enrichFindingsForExport(findings)
    derivePagesForExport(scanResult)
    enrichGroupsForExport(scanResult)
    sanitizeRequests(scanResult.requests)
    const stats = rebuildStats(findings)
    const attacksCount = Number(scanResult?.stats?.attacksCount || 0)
    if (attacksCount) stats.attacksCount = attacksCount
    scanResult.stats = stats
    try {
        const relatedScans = Array.isArray(opts.relatedScans) ? opts.relatedScans : []
        const extraEnginesPresent = Array.isArray(opts.extraEnginesPresent)
            ? opts.extraEnginesPresent
            : deriveExtraEnginesPresent(relatedScans)
        applyScanAnalysis(scanResult, {
            force: true,
            relatedScans,
            extraEnginesPresent
        })
    } catch (err) {
        try { console.warn("[PTK Export] scan analysis failed", err?.message || err) } catch (_) { }
    }
    if (!shouldIncludeScanAnalysisInExport(scanResult)) {
        delete scanResult.analysis
        delete scanResult.analysisVersion
    }
    if (shouldIncludeBugBountyData(opts)) {
        if (scanResult.bugbounty && typeof scanResult.bugbounty === "object") {
            scanResult.bugbounty = sanitizeBugBountyPayload(scanResult.bugbounty, opts)
        } else {
            delete scanResult.bugbounty
        }
        if (scanResult.bugBounty && typeof scanResult.bugBounty === "object") {
            scanResult.bugBounty = sanitizeBugBountyPayload(scanResult.bugBounty, opts)
        } else {
            delete scanResult.bugBounty
        }
    } else {
        delete scanResult.bugbounty
        delete scanResult.bugBounty
    }
    const sanitizedSettings = sanitizeScanConfiguration(scanResult.settings)
    scanResult.settings = sanitizedSettings
    scanResult.scanConfiguration = cloneValue(sanitizedSettings)
    sanitizeCodeArtifacts(scanResult.codeArtifacts)
    return scanResult
}

export function buildExportScanResult(scanId, opts = {}) {
    const source = resolveScanResult(scanId, opts.scanResult)
    if (!source) return null
    const cloned = cloneValue(source)
    const relatedScans = resolveRelatedScans(scanId, opts.relatedScans, source)
    const extraEnginesPresent = Array.isArray(opts.extraEnginesPresent)
        ? opts.extraEnginesPresent
        : deriveExtraEnginesPresent(relatedScans)
    return sanitizeScanResult(cloned, {
        ...opts,
        relatedScans,
        extraEnginesPresent
    })
}

export default buildExportScanResult
