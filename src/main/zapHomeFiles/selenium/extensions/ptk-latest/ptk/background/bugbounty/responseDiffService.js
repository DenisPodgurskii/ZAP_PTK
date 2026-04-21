import CryptoES from "../../packages/crypto-es/index.js"

function sha256(value) {
    return CryptoES.SHA256(String(value || "")).toString(CryptoES.enc.Hex)
}

function normalizeMethod(value) {
    const method = String(value || "GET").trim().toUpperCase()
    return method || "GET"
}

function normalizeHeaders(headers) {
    if (!headers) return {}
    if (Array.isArray(headers)) {
        return headers.reduce((acc, entry) => {
            const name = String(entry?.name || entry?.key || "").trim().toLowerCase()
            if (!name) return acc
            const value = String(entry?.value ?? "").trim()
            if (!acc[name]) acc[name] = []
            acc[name].push(value)
            return acc
        }, {})
    }
    if (typeof headers === "object") {
        return Object.entries(headers).reduce((acc, [name, value]) => {
            const key = String(name || "").trim().toLowerCase()
            if (!key) return acc
            acc[key] = [String(value ?? "").trim()]
            return acc
        }, {})
    }
    return {}
}

function stringifyHeaderValues(values = []) {
    return (Array.isArray(values) ? values : [])
        .map((value) => String(value ?? "").trim())
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b))
        .join("\n")
}

function extractStatus(response = {}) {
    const raw = response?.statusCode ?? response?.status ?? response?.code ?? null
    const numeric = Number(raw)
    return Number.isFinite(numeric) ? numeric : null
}

function extractBodyText(response = {}) {
    if (typeof response?.body === "string") return response.body
    if (typeof response?.text === "string") return response.text
    if (typeof response?.raw === "string") return response.raw
    if (response?.body && typeof response.body === "object") {
        try {
            return JSON.stringify(response.body)
        } catch (_) {
            return ""
        }
    }
    return ""
}

function firstHeader(headers = {}, name) {
    const key = String(name || "").trim().toLowerCase()
    const values = headers?.[key]
    if (!Array.isArray(values) || !values.length) return ""
    return String(values[0] || "")
}

function detectBodyKind(contentType = "", bodyText = "") {
    const normalizedType = String(contentType || "").toLowerCase()
    const trimmed = String(bodyText || "").trim()
    if (!trimmed) return "empty"
    if (normalizedType.includes("application/json")) return "json"
    if (normalizedType.includes("text/html")) return "html"
    if (normalizedType.includes("xml")) return "xml"
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "json"
    if (trimmed.startsWith("<!doctype html") || trimmed.startsWith("<html") || trimmed.includes("</")) return "html"
    return "text"
}

function safeJsonParse(bodyText = "", bodyKind = "") {
    if (bodyKind !== "json") return null
    try {
        return JSON.parse(bodyText)
    } catch (_) {
        return null
    }
}

function collectJsonPaths(value, prefix = "", depth = 0, acc = new Set()) {
    if (depth > 4 || value === null || value === undefined) return acc
    if (Array.isArray(value)) {
        acc.add(prefix || "[]")
        if (value.length) {
            collectJsonPaths(value[0], prefix ? `${prefix}[]` : "[]", depth + 1, acc)
        }
        return acc
    }
    if (typeof value === "object") {
        Object.keys(value).sort((a, b) => a.localeCompare(b)).forEach((key) => {
            const next = prefix ? `${prefix}.${key}` : key
            acc.add(next)
            collectJsonPaths(value[key], next, depth + 1, acc)
        })
        return acc
    }
    if (prefix) acc.add(prefix)
    return acc
}

function detectAuthPosture({ status = null, location = "", bodyText = "" } = {}) {
    const lowerLocation = String(location || "").toLowerCase()
    const lowerBody = String(bodyText || "").toLowerCase()
    if (status === 401 || status === 403) return "denied"
    if ((status === 301 || status === 302 || status === 303 || status === 307 || status === 308)
        && /(login|signin|auth|oauth|sso|session)/.test(lowerLocation)) {
        return "auth_redirect"
    }
    if (/(forbidden|unauthorized|access denied|login required|sign in)/.test(lowerBody)) {
        return "denied"
    }
    if (status !== null && status >= 200 && status < 400) return "allowed"
    return "unknown"
}

function detectMutationOutcome({
    status = null,
    authPosture = "unknown",
    redirectLocation = ""
} = {}) {
    if (authPosture === "denied") return "blocked"
    if (authPosture === "auth_redirect" || redirectLocation) return "redirected"
    if (status !== null && status >= 200 && status < 300) return "applied"
    return "unknown"
}

function diffHeaderMaps(baselineHeaders = {}, comparisonHeaders = {}) {
    const baselineKeys = new Set(Object.keys(baselineHeaders))
    const comparisonKeys = new Set(Object.keys(comparisonHeaders))
    const added = []
    const removed = []
    const changed = []

    comparisonKeys.forEach((key) => {
        if (!baselineKeys.has(key)) {
            added.push(key)
        }
    })
    baselineKeys.forEach((key) => {
        if (!comparisonKeys.has(key)) {
            removed.push(key)
        } else {
            const left = stringifyHeaderValues(baselineHeaders[key])
            const right = stringifyHeaderValues(comparisonHeaders[key])
            if (left !== right) {
                changed.push(key)
            }
        }
    })

    return {
        added: added.sort((a, b) => a.localeCompare(b)),
        removed: removed.sort((a, b) => a.localeCompare(b)),
        changed: changed.sort((a, b) => a.localeCompare(b))
    }
}

function diffStringSets(leftValues = [], rightValues = []) {
    const left = new Set(leftValues)
    const right = new Set(rightValues)
    const added = Array.from(right).filter((value) => !left.has(value)).sort((a, b) => a.localeCompare(b))
    const removed = Array.from(left).filter((value) => !right.has(value)).sort((a, b) => a.localeCompare(b))
    return { added, removed }
}

function buildObservations({
    baseline,
    comparison,
    headerDiff,
    jsonFieldDiff,
    indicators,
    requestMethod
}) {
    const observations = []
    if (baseline.status !== comparison.status) {
        observations.push(`Status changed from ${baseline.status ?? "unknown"} to ${comparison.status ?? "unknown"}.`)
    }
    if (indicators.authPostureChanged) {
        observations.push(`Authorization posture changed from ${baseline.authPosture} to ${comparison.authPosture}.`)
    }
    if (indicators.redirectChanged) {
        observations.push(`Redirect target changed from ${baseline.redirectLocation || "none"} to ${comparison.redirectLocation || "none"}.`)
    }
    if (jsonFieldDiff.added.length) {
        observations.push(`Comparison response exposed additional JSON fields: ${jsonFieldDiff.added.slice(0, 5).join(", ")}.`)
    }
    if (jsonFieldDiff.removed.length) {
        observations.push(`Comparison response removed JSON fields: ${jsonFieldDiff.removed.slice(0, 5).join(", ")}.`)
    }
    if (headerDiff.added.length || headerDiff.removed.length || headerDiff.changed.length) {
        const parts = []
        if (headerDiff.added.length) parts.push(`added headers ${headerDiff.added.join(", ")}`)
        if (headerDiff.removed.length) parts.push(`removed headers ${headerDiff.removed.join(", ")}`)
        if (headerDiff.changed.length) parts.push(`changed headers ${headerDiff.changed.join(", ")}`)
        observations.push(`Header set changed: ${parts.join("; ")}.`)
    }
    if (indicators.bodyLengthChanged && !jsonFieldDiff.added.length && !jsonFieldDiff.removed.length) {
        observations.push(`Body length changed from ${baseline.bodyLength} to ${comparison.bodyLength}.`)
    }
    if (indicators.mutationOutcomeChanged && ["POST", "PUT", "PATCH", "DELETE"].includes(requestMethod)) {
        observations.push("Mutation outcome changed across compared responses.")
    }
    return observations
}

export class ResponseDiffService {
    normalizeResponse(response = {}) {
        const headers = normalizeHeaders(response?.headers || response?.responseHeaders || {})
        const bodyText = extractBodyText(response)
        const contentType = firstHeader(headers, "content-type")
        const bodyKind = detectBodyKind(contentType, bodyText)
        const jsonBody = safeJsonParse(bodyText, bodyKind)
        const jsonFields = jsonBody ? Array.from(collectJsonPaths(jsonBody)).sort((a, b) => a.localeCompare(b)) : []
        const status = extractStatus(response)
        const redirectLocation = firstHeader(headers, "location")
        const authPosture = detectAuthPosture({
            status,
            location: redirectLocation,
            bodyText
        })
        return {
            status,
            headers,
            contentType,
            bodyText,
            bodyHash: sha256(bodyText),
            bodyKind,
            bodyLength: bodyText.length,
            jsonFields,
            redirectLocation,
            authPosture,
            mutationOutcome: detectMutationOutcome({
                status,
                authPosture,
                redirectLocation
            })
        }
    }

    diffResponses({
        baseline = {},
        comparison = {},
        requestMethod = "GET"
    } = {}) {
        const normalizedMethod = normalizeMethod(requestMethod)
        const left = this.normalizeResponse(baseline)
        const right = this.normalizeResponse(comparison)
        const headerDiff = diffHeaderMaps(left.headers, right.headers)
        const jsonFieldDiff = diffStringSets(left.jsonFields, right.jsonFields)
        const indicators = {
            statusChanged: left.status !== right.status,
            authPostureChanged: left.authPosture !== right.authPosture,
            redirectChanged: left.redirectLocation !== right.redirectLocation,
            contentTypeChanged: left.contentType !== right.contentType,
            bodyChanged: left.bodyHash !== right.bodyHash,
            bodyLengthChanged: left.bodyLength !== right.bodyLength,
            headerChanged: !!(headerDiff.added.length || headerDiff.removed.length || headerDiff.changed.length),
            fieldExposureChanged: !!(jsonFieldDiff.added.length || jsonFieldDiff.removed.length),
            responseShapeChanged: left.bodyKind !== right.bodyKind || !!(jsonFieldDiff.added.length || jsonFieldDiff.removed.length),
            mutationOutcomeChanged: ["POST", "PUT", "PATCH", "DELETE"].includes(normalizedMethod)
                && left.mutationOutcome !== right.mutationOutcome
                && (left.mutationOutcome !== "unknown" || right.mutationOutcome !== "unknown")
        }
        const observations = buildObservations({
            baseline: left,
            comparison: right,
            headerDiff,
            jsonFieldDiff,
            indicators,
            requestMethod: normalizedMethod
        })
        return {
            requestMethod: normalizedMethod,
            baseline: left,
            comparison: right,
            headerDiff,
            jsonFieldDiff,
            indicators,
            meaningfulDifference: indicators.statusChanged
                || indicators.authPostureChanged
                || indicators.redirectChanged
                || indicators.fieldExposureChanged
                || indicators.headerChanged
                || indicators.mutationOutcomeChanged
                || (indicators.bodyChanged && indicators.bodyLengthChanged),
            observations
        }
    }
}

export default ResponseDiffService
