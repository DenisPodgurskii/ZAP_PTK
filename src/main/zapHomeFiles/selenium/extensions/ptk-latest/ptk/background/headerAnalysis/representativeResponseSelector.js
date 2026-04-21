/* Author: PTK Team
 *
 * Picks a minimal set of representative HTTP responses to avoid scanning
 * the entire request corpus when evaluating headers.
 */

const SUCCESS_MIN = 200
const SUCCESS_MAX = 399

function toLower(value) {
    return typeof value === "string" ? value.toLowerCase() : ""
}

function getHeaderValue(headers = [], name) {
    const lname = String(name || "").toLowerCase()
    for (const header of headers) {
        if (!header || !header.name) continue
        if (header.name.toLowerCase() === lname) {
            return header.value || ""
        }
    }
    return ""
}

function isHtmlResponse(entry) {
    const contentType = toLower(
        entry.contentType ||
        getHeaderValue(entry.responseHeaders, "content-type")
    )
    return contentType.includes("text/html")
}

function normalizeRequests(requests = []) {
    return (requests || [])
        .map((req, index) => ({
            index,
            url: req?.url || "",
            method: req?.method || "GET",
            statusCode: req?.statusCode ?? req?.status ?? null,
            responseHeaders: Array.isArray(req?.responseHeaders) ? req.responseHeaders : [],
            requestHeaders: Array.isArray(req?.requestHeaders) ? req.requestHeaders : [],
            type: req?.type || req?.resourceType || "",
            frameId: req?.frameId ?? null,
            tabId: req?.tabId ?? null,
            timeStamp: req?.timeStamp || req?.timestamp || Date.now(),
        }))
        .filter((entry) => entry.responseHeaders.length)
}

function sameOrigin(urlA, urlB) {
    try {
        const a = new URL(urlA)
        const b = new URL(urlB)
        return a.origin === b.origin
    } catch (_) {
        return false
    }
}

function sameUrl(a, b) {
    try {
        const urlA = new URL(a)
        const urlB = new URL(b)
        return urlA.origin === urlB.origin && urlA.pathname === urlB.pathname
    } catch (_) {
        return false
    }
}

function isSuccessful(entry) {
    const status = Number(entry.statusCode)
    if (Number.isNaN(status)) return false
    return status >= SUCCESS_MIN && status <= SUCCESS_MAX
}

export function selectRepresentativeResponses(requests = [], tabUrl = "") {
    const normalized = normalizeRequests(requests)
    if (!normalized.length) {
        return []
    }

    const sorted = normalized.sort((a, b) => (b.timeStamp || 0) - (a.timeStamp || 0))
    const selected = []

    const primary = sorted.find(
        (entry) =>
            isSuccessful(entry) &&
            entry.type === "main_frame" &&
            tabUrl &&
            sameUrl(entry.url, tabUrl)
    )

    if (primary) {
        selected.push(primary)
    }

    const originMatches = sorted.filter(
        (entry) =>
            entry !== primary &&
            isSuccessful(entry) &&
            tabUrl &&
            sameOrigin(entry.url, tabUrl) &&
            (entry.type === "main_frame" ||
                entry.type === "sub_frame" ||
                isHtmlResponse(entry))
    )

    for (const candidate of originMatches) {
        if (selected.length >= 2) break
        selected.push(candidate)
    }

    if (selected.length < 2) {
        for (const candidate of sorted) {
            if (selected.length >= 2) break
            if (selected.includes(candidate)) continue
            selected.push(candidate)
        }
    }

    return selected.slice(0, 2)
}

export function buildPassiveOriginal(response) {
    if (!response) {
        return null
    }

    const url = response.url || ""
    return {
        url,
        request: {
            url,
            headers: Array.isArray(response.requestHeaders)
                ? response.requestHeaders
                : [],
        },
        response: {
            url,
            headers: Array.isArray(response.responseHeaders)
                ? response.responseHeaders
                : [],
            status: response.statusCode ?? response.status ?? null,
            statusCode: response.statusCode ?? response.status ?? null,
            isHttps: (url || "").startsWith("https://"),
        },
    }
}
