import { buildRouteKey, normalizeEngineName, normalizeMethod, splitRouteKey } from "./canonicalize.js"
import { normalizeEvidenceRefs } from "./evidenceRefs.js"

const ENGINE_ORDER = Object.freeze(["DAST", "IAST", "SAST", "SCA"])
const MAX_SECTION_ITEMS = 75

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function uniqueStrings(values = []) {
    return Array.from(
        new Set(
            (Array.isArray(values) ? values : [])
                .map((value) => toNonEmptyString(value))
                .filter(Boolean)
        )
    ).sort((a, b) => a.localeCompare(b))
}

function sortEngines(values = []) {
    return Array.from(
        new Set(
            (Array.isArray(values) ? values : [])
                .map((value) => normalizeEngineName(value))
                .filter(Boolean)
        )
    ).sort((left, right) => {
        const leftIndex = ENGINE_ORDER.indexOf(left)
        const rightIndex = ENGINE_ORDER.indexOf(right)
        if (leftIndex === -1 && rightIndex === -1) return left.localeCompare(right)
        if (leftIndex === -1) return 1
        if (rightIndex === -1) return -1
        return leftIndex - rightIndex
    })
}

function parseUrl(value, hostHint = null) {
    const raw = toNonEmptyString(value)
    if (!raw) return null
    const base = `http://${String(hostHint || "localhost").trim() || "localhost"}`
    try {
        return new URL(raw, base)
    } catch (_) {
        return null
    }
}

function routePathFromUrl(value, hostHint = null) {
    const parsed = parseUrl(value, hostHint)
    if (!parsed) return "/"
    if (parsed.hash && /^#?!?\//.test(parsed.hash)) {
        const hash = parsed.hash.startsWith("#!") ? parsed.hash.slice(2) : parsed.hash.slice(1)
        const queryIndex = hash.indexOf("?")
        return queryIndex >= 0 ? hash.slice(0, queryIndex) : hash
    }
    return parsed.pathname || "/"
}

function queryParamNamesFromUrl(value, hostHint = null) {
    const parsed = parseUrl(value, hostHint)
    if (!parsed) return []
    return uniqueStrings(Array.from(parsed.searchParams.keys()))
}

function parseHeaderEntries(headers) {
    if (Array.isArray(headers)) {
        return headers
            .map((entry) => {
                const name = toNonEmptyString(entry?.name)
                const value = toNonEmptyString(entry?.value)
                if (!name) return null
                return { name, value: value || "" }
            })
            .filter(Boolean)
    }
    if (headers && typeof headers === "object") {
        return Object.keys(headers).map((name) => ({
            name,
            value: headers[name] === undefined || headers[name] === null ? "" : String(headers[name])
        }))
    }
    return []
}

function findHeaderValue(headers, headerName) {
    const needle = String(headerName || "").trim().toLowerCase()
    if (!needle) return null
    const match = parseHeaderEntries(headers).find((entry) => String(entry?.name || "").trim().toLowerCase() === needle)
    return toNonEmptyString(match?.value)
}

function parseBodyKeys(body) {
    if (!body) return []
    if (body && typeof body === "object" && !Array.isArray(body)) {
        return uniqueStrings(Object.keys(body))
    }
    const text = String(body || "").trim()
    if (!text) return []
    try {
        const parsed = JSON.parse(text)
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
            return uniqueStrings(Object.keys(parsed))
        }
    } catch (_) { }
    try {
        const params = new URLSearchParams(text)
        return uniqueStrings(Array.from(params.keys()))
    } catch (_) {
        return []
    }
}

function buildRouteEvidenceRef({ type = "artifact", id = null, routeKey = null, method = null, param = null, kind = null } = {}) {
    return {
        type,
        id: toNonEmptyString(id),
        loc: {
            ...(routeKey ? { route: routeKey } : {}),
            ...(method ? { method: normalizeMethod(method) } : {}),
            ...(param ? { param } : {}),
            ...(kind ? { kind } : {})
        }
    }
}

function mergeEvidenceRefs(current = [], incoming = []) {
    return normalizeEvidenceRefs([...(Array.isArray(current) ? current : []), ...(Array.isArray(incoming) ? incoming : [])], { maxRefs: 12 })
}

function ensureMapEntry(map, id, factory) {
    if (!map.has(id)) {
        map.set(id, factory())
    }
    return map.get(id)
}

function finalizeRouteEntry(entry = {}) {
    const routeParts = splitRouteKey(entry.routeKey)
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        path: entry.path || routeParts.pathTemplate || "/",
        routeType: entry.routeType || "route",
        enginesPresent: sortEngines(entry.enginesPresent),
        sources: uniqueStrings(entry.sources),
        authHints: uniqueStrings(entry.authHints),
        protocolHints: uniqueStrings(entry.protocolHints),
        environmentHints: uniqueStrings(entry.environmentHints),
        frameworks: uniqueStrings(entry.frameworks),
        sourceKinds: uniqueStrings(entry.sourceKinds),
        hintNames: uniqueStrings(entry.hintNames),
        pageUrls: uniqueStrings(entry.pageUrls),
        adminLike: entry.adminLike === true,
        evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs || [])
    }
}

function finalizeEndpointEntry(entry = {}) {
    const routeParts = splitRouteKey(entry.routeKey)
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        method: normalizeMethod(entry.method || routeParts.method || "GET"),
        path: entry.path || routeParts.pathTemplate || "/",
        url: entry.url || null,
        enginesPresent: sortEngines(entry.enginesPresent),
        sources: uniqueStrings(entry.sources),
        transports: uniqueStrings(entry.transports),
        authHints: uniqueStrings(entry.authHints),
        contentTypes: uniqueStrings(entry.contentTypes),
        paramNames: uniqueStrings(entry.paramNames),
        bodyKeys: uniqueStrings(entry.bodyKeys),
        headerNames: uniqueStrings(entry.headerNames),
        discoveryTags: uniqueStrings(entry.discoveryTags),
        environmentHints: uniqueStrings(entry.environmentHints),
        pageUrls: uniqueStrings(entry.pageUrls),
        adminLike: entry.adminLike === true,
        evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs || [])
    }
}

function finalizeGraphqlEntry(entry = {}) {
    const routeParts = splitRouteKey(entry.routeKey)
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        method: normalizeMethod(entry.method || routeParts.method || "POST"),
        path: entry.path || routeParts.pathTemplate || "/graphql",
        url: entry.url || null,
        enginesPresent: sortEngines(entry.enginesPresent),
        transports: uniqueStrings(entry.transports),
        authHints: uniqueStrings(entry.authHints),
        operationTypes: uniqueStrings(entry.operationTypes),
        operationNames: uniqueStrings(entry.operationNames),
        rootFields: uniqueStrings(entry.rootFields),
        variableNames: uniqueStrings(entry.variableNames),
        pageUrls: uniqueStrings(entry.pageUrls),
        adminLike: entry.adminLike === true,
        evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs || [])
    }
}

function finalizeHiddenParamEntry(entry = {}) {
    const routeParts = splitRouteKey(entry.routeKey)
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        method: normalizeMethod(entry.method || routeParts.method || "GET"),
        path: entry.path || routeParts.pathTemplate || "/",
        paramName: entry.paramName || null,
        container: entry.container || "query",
        hintTypes: uniqueStrings(entry.hintTypes),
        actions: uniqueStrings(entry.actions),
        enginesPresent: sortEngines(entry.enginesPresent),
        pageUrls: uniqueStrings(entry.pageUrls),
        adminLike: entry.adminLike === true,
        evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs || [])
    }
}

function finalizeSurfaceEntry(entry = {}) {
    const routeParts = splitRouteKey(entry.routeKey)
    return {
        id: entry.id || null,
        routeKey: entry.routeKey || null,
        path: entry.path || routeParts.pathTemplate || "/",
        surfaceType: entry.surfaceType || "surface",
        label: entry.label || null,
        hintNames: uniqueStrings(entry.hintNames),
        enginesPresent: sortEngines(entry.enginesPresent),
        pageUrls: uniqueStrings(entry.pageUrls),
        adminLike: entry.adminLike === true,
        evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs || [])
    }
}

function compareRouteEntries(left = {}, right = {}) {
    if ((right.adminLike ? 1 : 0) !== (left.adminLike ? 1 : 0)) return (right.adminLike ? 1 : 0) - (left.adminLike ? 1 : 0)
    const engineDelta = (right.enginesPresent || []).length - (left.enginesPresent || []).length
    if (engineDelta !== 0) return engineDelta
    const hintDelta = ((right.authHints || []).length + (right.hintNames || []).length) - ((left.authHints || []).length + (left.hintNames || []).length)
    if (hintDelta !== 0) return hintDelta
    return `${left.path || ""}`.localeCompare(`${right.path || ""}`)
}

function compareEndpointEntries(left = {}, right = {}) {
    if ((right.adminLike ? 1 : 0) !== (left.adminLike ? 1 : 0)) return (right.adminLike ? 1 : 0) - (left.adminLike ? 1 : 0)
    const engineDelta = (right.enginesPresent || []).length - (left.enginesPresent || []).length
    if (engineDelta !== 0) return engineDelta
    const signalDelta = (
        (right.authHints || []).length
        + (right.discoveryTags || []).length
        + (right.paramNames || []).length
        + (right.bodyKeys || []).length
    ) - (
        (left.authHints || []).length
        + (left.discoveryTags || []).length
        + (left.paramNames || []).length
        + (left.bodyKeys || []).length
    )
    if (signalDelta !== 0) return signalDelta
    return `${left.method || ""} ${left.path || ""}`.localeCompare(`${right.method || ""} ${right.path || ""}`)
}

function compareHiddenParamEntries(left = {}, right = {}) {
    if ((right.adminLike ? 1 : 0) !== (left.adminLike ? 1 : 0)) return (right.adminLike ? 1 : 0) - (left.adminLike ? 1 : 0)
    const hintDelta = (right.hintTypes || []).length - (left.hintTypes || []).length
    if (hintDelta !== 0) return hintDelta
    return `${left.paramName || ""}`.localeCompare(`${right.paramName || ""}`)
}

function compareSurfaceEntries(left = {}, right = {}) {
    if ((right.adminLike ? 1 : 0) !== (left.adminLike ? 1 : 0)) return (right.adminLike ? 1 : 0) - (left.adminLike ? 1 : 0)
    const hintDelta = (right.hintNames || []).length - (left.hintNames || []).length
    if (hintDelta !== 0) return hintDelta
    return `${left.label || ""}`.localeCompare(`${right.label || ""}`)
}

function compareGraphqlEntries(left = {}, right = {}) {
    if ((right.adminLike ? 1 : 0) !== (left.adminLike ? 1 : 0)) return (right.adminLike ? 1 : 0) - (left.adminLike ? 1 : 0)
    const signalDelta = (
        (right.operationTypes || []).length
        + (right.operationNames || []).length
        + (right.rootFields || []).length
        + (right.variableNames || []).length
    ) - (
        (left.operationTypes || []).length
        + (left.operationNames || []).length
        + (left.rootFields || []).length
        + (left.variableNames || []).length
    )
    if (signalDelta !== 0) return signalDelta
    return `${left.path || ""}`.localeCompare(`${right.path || ""}`)
}

function routeTypeFromRuntimeEvent(event = {}, routeValue = "") {
    const sourceKind = String(event?.sourceKind || event?.source?.kind || "").trim().toLowerCase()
    if (sourceKind === "hashroute" || sourceKind === "clientroute" || sourceKind === "historystate") return "spa"
    if (String(routeValue || "").includes("#/")) return "spa"
    return "runtime"
}

function addRouteEntry(routeMap, {
    id = null,
    routeKey = null,
    routeType = "route",
    engine = null,
    source = null,
    authHints = [],
    protocolHints = [],
    environmentHints = [],
    frameworks = [],
    sourceKinds = [],
    hintNames = [],
    pageUrls = [],
    adminLike = false,
    evidenceRefs = []
} = {}) {
    const normalizedRouteKey = toNonEmptyString(routeKey)
    if (!normalizedRouteKey) return
    const routeParts = splitRouteKey(normalizedRouteKey)
    const entryId = `${routeType}:${normalizedRouteKey}`
    const entry = ensureMapEntry(routeMap, entryId, () => ({
        id: entryId,
        routeKey: normalizedRouteKey,
        path: routeParts.pathTemplate || "/",
        routeType,
        enginesPresent: [],
        sources: [],
        authHints: [],
        protocolHints: [],
        environmentHints: [],
        frameworks: [],
        sourceKinds: [],
        hintNames: [],
        pageUrls: [],
        adminLike: false,
        evidenceRefs: []
    }))
    entry.enginesPresent.push(engine)
    if (source) entry.sources.push(source)
    entry.authHints.push(...(Array.isArray(authHints) ? authHints : []))
    entry.protocolHints.push(...(Array.isArray(protocolHints) ? protocolHints : []))
    entry.environmentHints.push(...(Array.isArray(environmentHints) ? environmentHints : []))
    entry.frameworks.push(...(Array.isArray(frameworks) ? frameworks : []))
    entry.sourceKinds.push(...(Array.isArray(sourceKinds) ? sourceKinds : []))
    entry.hintNames.push(...(Array.isArray(hintNames) ? hintNames : []))
    entry.pageUrls.push(...(Array.isArray(pageUrls) ? pageUrls : []))
    if (adminLike) entry.adminLike = true
    entry.evidenceRefs = mergeEvidenceRefs(entry.evidenceRefs, evidenceRefs)
    if (id && !entry.id) entry.id = id
}

function addEndpointEntry(endpointMap, {
    routeKey = null,
    method = "GET",
    url = null,
    engine = null,
    source = null,
    transport = null,
    authHints = [],
    contentTypes = [],
    paramNames = [],
    bodyKeys = [],
    headerNames = [],
    discoveryTags = [],
    environmentHints = [],
    pageUrls = [],
    adminLike = false,
    evidenceRefs = []
} = {}) {
    const normalizedRouteKey = toNonEmptyString(routeKey)
    if (!normalizedRouteKey) return
    const routeParts = splitRouteKey(normalizedRouteKey)
    const entryId = `endpoint:${normalizedRouteKey}`
    const entry = ensureMapEntry(endpointMap, entryId, () => ({
        id: entryId,
        routeKey: normalizedRouteKey,
        method: normalizeMethod(method || routeParts.method || "GET"),
        path: routeParts.pathTemplate || "/",
        url: toNonEmptyString(url),
        enginesPresent: [],
        sources: [],
        transports: [],
        authHints: [],
        contentTypes: [],
        paramNames: [],
        bodyKeys: [],
        headerNames: [],
        discoveryTags: [],
        environmentHints: [],
        pageUrls: [],
        adminLike: false,
        evidenceRefs: []
    }))
    entry.enginesPresent.push(engine)
    if (source) entry.sources.push(source)
    if (transport) entry.transports.push(transport)
    entry.authHints.push(...(Array.isArray(authHints) ? authHints : []))
    entry.contentTypes.push(...(Array.isArray(contentTypes) ? contentTypes : []))
    entry.paramNames.push(...(Array.isArray(paramNames) ? paramNames : []))
    entry.bodyKeys.push(...(Array.isArray(bodyKeys) ? bodyKeys : []))
    entry.headerNames.push(...(Array.isArray(headerNames) ? headerNames : []))
    entry.discoveryTags.push(...(Array.isArray(discoveryTags) ? discoveryTags : []))
    entry.environmentHints.push(...(Array.isArray(environmentHints) ? environmentHints : []))
    entry.pageUrls.push(...(Array.isArray(pageUrls) ? pageUrls : []))
    if (!entry.url && url) entry.url = toNonEmptyString(url)
    if (adminLike) entry.adminLike = true
    entry.evidenceRefs = mergeEvidenceRefs(entry.evidenceRefs, evidenceRefs)
}

function addGraphqlEntry(graphqlMap, {
    routeKey = null,
    method = "POST",
    url = null,
    engine = null,
    transport = null,
    authHints = [],
    operationTypes = [],
    operationNames = [],
    rootFields = [],
    variableNames = [],
    pageUrls = [],
    adminLike = false,
    evidenceRefs = []
} = {}) {
    const normalizedRouteKey = toNonEmptyString(routeKey)
    if (!normalizedRouteKey) return
    const routeParts = splitRouteKey(normalizedRouteKey)
    const entryId = `graphql:${normalizedRouteKey}`
    const entry = ensureMapEntry(graphqlMap, entryId, () => ({
        id: entryId,
        routeKey: normalizedRouteKey,
        method: normalizeMethod(method || routeParts.method || "POST"),
        path: routeParts.pathTemplate || "/graphql",
        url: toNonEmptyString(url),
        enginesPresent: [],
        transports: [],
        authHints: [],
        operationTypes: [],
        operationNames: [],
        rootFields: [],
        variableNames: [],
        pageUrls: [],
        adminLike: false,
        evidenceRefs: []
    }))
    entry.enginesPresent.push(engine)
    if (transport) entry.transports.push(transport)
    entry.authHints.push(...(Array.isArray(authHints) ? authHints : []))
    entry.operationTypes.push(...(Array.isArray(operationTypes) ? operationTypes : []))
    entry.operationNames.push(...(Array.isArray(operationNames) ? operationNames : []))
    entry.rootFields.push(...(Array.isArray(rootFields) ? rootFields : []))
    entry.variableNames.push(...(Array.isArray(variableNames) ? variableNames : []))
    entry.pageUrls.push(...(Array.isArray(pageUrls) ? pageUrls : []))
    if (!entry.url && url) entry.url = toNonEmptyString(url)
    if (adminLike) entry.adminLike = true
    entry.evidenceRefs = mergeEvidenceRefs(entry.evidenceRefs, evidenceRefs)
}

function addHiddenParamEntry(hiddenParamMap, {
    routeKey = null,
    method = "GET",
    paramName = null,
    container = "query",
    hintTypes = [],
    actions = [],
    engine = null,
    pageUrls = [],
    adminLike = false,
    evidenceRefs = []
} = {}) {
    const normalizedRouteKey = toNonEmptyString(routeKey)
    const normalizedParamName = toNonEmptyString(paramName)
    if (!normalizedRouteKey || !normalizedParamName) return
    const routeParts = splitRouteKey(normalizedRouteKey)
    const entryId = `hidden:${normalizedRouteKey}|${String(container || "query").toLowerCase()}|${normalizedParamName}`
    const entry = ensureMapEntry(hiddenParamMap, entryId, () => ({
        id: entryId,
        routeKey: normalizedRouteKey,
        method: normalizeMethod(method || routeParts.method || "GET"),
        path: routeParts.pathTemplate || "/",
        paramName: normalizedParamName,
        container: String(container || "query").toLowerCase(),
        hintTypes: [],
        actions: [],
        enginesPresent: [],
        pageUrls: [],
        adminLike: false,
        evidenceRefs: []
    }))
    entry.enginesPresent.push(engine)
    entry.hintTypes.push(...(Array.isArray(hintTypes) ? hintTypes : []))
    entry.actions.push(...(Array.isArray(actions) ? actions : []))
    entry.pageUrls.push(...(Array.isArray(pageUrls) ? pageUrls : []))
    if (adminLike) entry.adminLike = true
    entry.evidenceRefs = mergeEvidenceRefs(entry.evidenceRefs, evidenceRefs)
}

function addSurfaceEntry(surfaceMap, {
    routeKey = null,
    surfaceType = "surface",
    label = null,
    hintNames = [],
    engine = null,
    pageUrls = [],
    adminLike = false,
    evidenceRefs = []
} = {}) {
    const normalizedRouteKey = toNonEmptyString(routeKey)
    const normalizedLabel = toNonEmptyString(label)
    if (!normalizedRouteKey || !normalizedLabel) return
    const routeParts = splitRouteKey(normalizedRouteKey)
    const entryId = `surface:${normalizedRouteKey}|${String(surfaceType || "surface").toLowerCase()}|${normalizedLabel}`
    const entry = ensureMapEntry(surfaceMap, entryId, () => ({
        id: entryId,
        routeKey: normalizedRouteKey,
        path: routeParts.pathTemplate || "/",
        surfaceType: String(surfaceType || "surface").toLowerCase(),
        label: normalizedLabel,
        hintNames: [],
        enginesPresent: [],
        pageUrls: [],
        adminLike: false,
        evidenceRefs: []
    }))
    entry.enginesPresent.push(engine)
    entry.hintNames.push(...(Array.isArray(hintNames) ? hintNames : []))
    entry.pageUrls.push(...(Array.isArray(pageUrls) ? pageUrls : []))
    if (adminLike) entry.adminLike = true
    entry.evidenceRefs = mergeEvidenceRefs(entry.evidenceRefs, evidenceRefs)
}

function consumeDastRequest(endpointMap, routeMap, record = {}, hostHint = null) {
    const requestId = toNonEmptyString(record?.id)
    const originalRequest = record?.original?.request && typeof record.original.request === "object"
        ? record.original.request
        : {}
    const originalResponse = record?.original?.response && typeof record.original.response === "object"
        ? record.original.response
        : {}
    const method = normalizeMethod(originalRequest?.method || "GET")
    const url = originalRequest?.url || null
    if (url) {
        const routeKey = buildRouteKey({ url, method, host: hostHint })
        const headerEntries = parseHeaderEntries(originalRequest?.headers)
        const headerNames = uniqueStrings(headerEntries.map((entry) => entry.name))
        const authHints = uniqueStrings(headerEntries
            .filter((entry) => /authorization|cookie|x-api-key|x-auth|csrf/i.test(String(entry?.name || "")))
            .map((entry) => entry.name))
        const contentTypes = uniqueStrings([
            findHeaderValue(originalRequest?.headers, "content-type"),
            findHeaderValue(originalResponse?.headers, "content-type")
        ])
        const paramNames = queryParamNamesFromUrl(url, hostHint)
        const bodyKeys = parseBodyKeys(originalRequest?.body || originalRequest?.postData || null)
        addEndpointEntry(endpointMap, {
            routeKey,
            method,
            url,
            engine: "DAST",
            source: "request",
            transport: "http",
            authHints,
            contentTypes,
            paramNames,
            bodyKeys,
            headerNames,
            evidenceRefs: [buildRouteEvidenceRef({ type: "request", id: requestId, routeKey, method })]
        })
        if (method === "GET" && !routePathFromUrl(url, hostHint).startsWith("/api")) {
            addRouteEntry(routeMap, {
                routeKey,
                routeType: String(url || "").includes("#/") ? "spa" : "page",
                engine: "DAST",
                source: "request",
                pageUrls: [url],
                evidenceRefs: [buildRouteEvidenceRef({ type: "request", id: requestId, routeKey, method })]
            })
        }
    }
    const attacks = Array.isArray(record?.attacks) ? record.attacks : []
    attacks.forEach((attack) => {
        const attackRequest = attack?.request && typeof attack.request === "object" ? attack.request : {}
        const attackUrl = attackRequest?.url || url || null
        if (!attackUrl) return
        const attackMethod = normalizeMethod(attackRequest?.method || method)
        const routeKey = buildRouteKey({ url: attackUrl, method: attackMethod, host: hostHint })
        addEndpointEntry(endpointMap, {
            routeKey,
            method: attackMethod,
            url: attackUrl,
            engine: "DAST",
            source: "attack",
            transport: "http",
            paramNames: uniqueStrings([
                ...queryParamNamesFromUrl(attackUrl, hostHint),
                attack?.param
            ]),
            evidenceRefs: [
                buildRouteEvidenceRef({ type: "attack", id: attack?.id || null, routeKey, method: attackMethod, param: attack?.param || null })
            ]
        })
    })
}

function consumeIastRequest(endpointMap, routeMap, record = {}, hostHint = null) {
    const requestId = toNonEmptyString(record?.id || record?.key)
    const method = normalizeMethod(record?.method || "GET")
    const url = record?.url || record?.displayUrl || null
    if (!url) return
    const routeKey = buildRouteKey({ url, method, host: hostHint })
    addEndpointEntry(endpointMap, {
        routeKey,
        method,
        url,
        engine: "IAST",
        source: "request",
        transport: record?.type || "http",
        contentTypes: [record?.mimeType],
        evidenceRefs: [buildRouteEvidenceRef({ type: "request", id: requestId, routeKey, method })]
    })
    if (method === "GET" && !routePathFromUrl(url, hostHint).startsWith("/api")) {
        addRouteEntry(routeMap, {
            routeKey,
            routeType: String(url || "").includes("#/") ? "spa" : "runtime",
            engine: "IAST",
            source: "request",
            pageUrls: [url],
            evidenceRefs: [buildRouteEvidenceRef({ type: "request", id: requestId, routeKey, method })]
        })
    }
}

function consumeRuntimeEvent(routeMap, event = {}, hostHint = null) {
    const routeValue = toNonEmptyString(
        event?.route
        || event?.url
        || event?.location?.url
        || event?.routing?.runtimeUrl
        || event?.routing?.url
    )
    if (!routeValue) return
    const method = normalizeMethod(event?.method || event?.location?.method || event?.routing?.method || "GET")
    const routeKey = buildRouteKey({ url: routeValue, method, host: hostHint })
    const sourceKind = toNonEmptyString(event?.sourceKind || event?.source?.kind)
    addRouteEntry(routeMap, {
        routeKey,
        routeType: routeTypeFromRuntimeEvent(event, routeValue),
        engine: normalizeEngineName(event?.engine) || "IAST",
        source: "runtime_event",
        sourceKinds: sourceKind ? [sourceKind] : [],
        pageUrls: [routeValue],
        evidenceRefs: [buildRouteEvidenceRef({ type: "runtimeEvent", id: event?.id || null, routeKey, method })]
    })
}

function consumeSastArtifacts(routeMap, endpointMap, graphqlMap, hiddenParamMap, surfaceMap, sastArtifacts = {}, hostHint = null) {
    const routes = Array.isArray(sastArtifacts?.routes) ? sastArtifacts.routes : []
    routes.forEach((artifact) => {
        const routeKey = artifact?.routeKey || buildRouteKey({
            url: artifact?.path || artifact?.pageUrl || "/",
            method: artifact?.method || "*",
            host: hostHint
        })
        addRouteEntry(routeMap, {
            routeKey,
            routeType: "spa",
            engine: "SAST",
            source: "code_route",
            authHints: artifact?.authHints,
            protocolHints: artifact?.protocolHints,
            environmentHints: artifact?.environmentHints,
            frameworks: [artifact?.framework],
            pageUrls: artifact?.pageUrls || [artifact?.pageUrl],
            adminLike: artifact?.adminLike === true,
            evidenceRefs: [buildRouteEvidenceRef({ type: "artifact", id: artifact?.id || null, routeKey, kind: "route" })]
        })
    })

    const endpoints = Array.isArray(sastArtifacts?.endpoints) ? sastArtifacts.endpoints : []
    endpoints.forEach((artifact) => {
        const routeKey = artifact?.routeKey || buildRouteKey({
            url: artifact?.resolvedUrl || artifact?.url || "/",
            method: artifact?.method || "GET",
            host: hostHint
        })
        addEndpointEntry(endpointMap, {
            routeKey,
            method: artifact?.method || "GET",
            url: artifact?.resolvedUrl || artifact?.url || null,
            engine: "SAST",
            source: "code_endpoint",
            transport: artifact?.transport || "http",
            authHints: artifact?.authHints,
            paramNames: artifact?.paramNames,
            bodyKeys: artifact?.bodyKeys,
            headerNames: artifact?.headerNames,
            discoveryTags: artifact?.discoveryTags,
            environmentHints: artifact?.environmentHints,
            pageUrls: artifact?.pageUrls || [artifact?.pageUrl],
            adminLike: artifact?.adminLike === true,
            evidenceRefs: [buildRouteEvidenceRef({ type: "artifact", id: artifact?.id || null, routeKey, method: artifact?.method || "GET", kind: "endpoint" })]
        })
    })

    const graphql = Array.isArray(sastArtifacts?.graphql) ? sastArtifacts.graphql : []
    graphql.forEach((artifact) => {
        const routeKey = artifact?.routeKey || buildRouteKey({
            url: artifact?.resolvedUrl || artifact?.url || "/graphql",
            method: artifact?.method || "POST",
            host: hostHint
        })
        addGraphqlEntry(graphqlMap, {
            routeKey,
            method: artifact?.method || "POST",
            url: artifact?.resolvedUrl || artifact?.url || null,
            engine: "SAST",
            transport: artifact?.transport || artifact?.clientKind || "graphql",
            authHints: artifact?.authHints,
            operationTypes: artifact?.operationTypes,
            operationNames: artifact?.operationNames,
            rootFields: artifact?.rootFields,
            variableNames: artifact?.variableNames,
            pageUrls: artifact?.pageUrls || [artifact?.pageUrl],
            adminLike: artifact?.adminLike === true,
            evidenceRefs: [buildRouteEvidenceRef({ type: "artifact", id: artifact?.id || null, routeKey, method: artifact?.method || "POST", kind: "graphql" })]
        })
    })

    const hiddenParams = Array.isArray(sastArtifacts?.hiddenParams) ? sastArtifacts.hiddenParams : []
    hiddenParams.forEach((artifact) => {
        const routeKey = artifact?.routeKey || buildRouteKey({
            url: artifact?.pageUrl || "/",
            method: artifact?.method || "GET",
            host: hostHint
        })
        addHiddenParamEntry(hiddenParamMap, {
            routeKey,
            method: artifact?.method || "GET",
            paramName: artifact?.paramName,
            container: artifact?.container || "query",
            hintTypes: artifact?.hintTypes || [artifact?.hintType],
            actions: artifact?.actions || [artifact?.action],
            engine: "SAST",
            pageUrls: artifact?.pageUrls || [artifact?.pageUrl],
            adminLike: artifact?.adminLike === true,
            evidenceRefs: [buildRouteEvidenceRef({ type: "artifact", id: artifact?.id || null, routeKey, method: artifact?.method || "GET", param: artifact?.paramName || null, kind: "hidden_param" })]
        })
    })

    const surfaces = Array.isArray(sastArtifacts?.surfaces) ? sastArtifacts.surfaces : []
    surfaces.forEach((artifact) => {
        const routeKey = artifact?.routeKey || buildRouteKey({
            url: artifact?.pageUrl || "/",
            method: "*",
            host: hostHint
        })
        addSurfaceEntry(surfaceMap, {
            routeKey,
            surfaceType: artifact?.surfaceType || "surface",
            label: artifact?.label,
            hintNames: artifact?.hintNames,
            engine: "SAST",
            pageUrls: artifact?.pageUrls || [artifact?.pageUrl],
            adminLike: artifact?.adminLike === true,
            evidenceRefs: [buildRouteEvidenceRef({ type: "artifact", id: artifact?.id || null, routeKey, kind: "surface" })]
        })
        addRouteEntry(routeMap, {
            routeKey,
            routeType: "spa",
            engine: "SAST",
            source: "code_surface",
            hintNames: artifact?.hintNames || [artifact?.label],
            pageUrls: artifact?.pageUrls || [artifact?.pageUrl],
            adminLike: artifact?.adminLike === true,
            evidenceRefs: [buildRouteEvidenceRef({ type: "artifact", id: artifact?.id || null, routeKey, kind: "surface" })]
        })
    })
}

function finalizeSection(map, finalizer, compare) {
    return Array.from(map.values())
        .map(finalizer)
        .sort(compare)
        .slice(0, MAX_SECTION_ITEMS)
}

export function buildApiExplorer(scanResult = {}, { relatedScans = [] } = {}) {
    const routeMap = new Map()
    const endpointMap = new Map()
    const graphqlMap = new Map()
    const hiddenParamMap = new Map()
    const surfaceMap = new Map()
    const gadgetMap = new Map()

    const consumeScan = (scan) => {
        if (!scan || typeof scan !== "object") return
        const engine = normalizeEngineName(scan?.engine) || null
        const hostHint = toNonEmptyString(scan?.host) || toNonEmptyString(scanResult?.host)
        const requests = Array.isArray(scan?.requests) ? scan.requests : []
        if (engine === "DAST") {
            requests.forEach((record) => consumeDastRequest(endpointMap, routeMap, record, hostHint))
        } else if (engine === "IAST") {
            requests.forEach((record) => consumeIastRequest(endpointMap, routeMap, record, hostHint))
        }
        const runtimeEvents = Array.isArray(scan?.runtimeEvents) ? scan.runtimeEvents : []
        runtimeEvents.forEach((event) => consumeRuntimeEvent(routeMap, event, hostHint))
        const sastArtifacts = scan?.codeArtifacts?.sast && typeof scan.codeArtifacts.sast === "object"
            ? scan.codeArtifacts.sast
            : null
        if (sastArtifacts) {
            consumeSastArtifacts(routeMap, endpointMap, graphqlMap, hiddenParamMap, surfaceMap, sastArtifacts, hostHint)
        }
    }

    consumeScan(scanResult)
    ;(Array.isArray(relatedScans) ? relatedScans : []).forEach((scan) => consumeScan(scan))

    const routes = finalizeSection(routeMap, finalizeRouteEntry, compareRouteEntries)
    const endpoints = finalizeSection(endpointMap, finalizeEndpointEntry, compareEndpointEntries)
    const graphql = finalizeSection(graphqlMap, finalizeGraphqlEntry, compareGraphqlEntries)
    const hiddenParams = finalizeSection(hiddenParamMap, finalizeHiddenParamEntry, compareHiddenParamEntries)
    const surfaces = finalizeSection(surfaceMap, finalizeSurfaceEntry, compareSurfaceEntries)
    const gadgets = finalizeSection(gadgetMap, finalizeSurfaceEntry, compareSurfaceEntries)

    return {
        summary: {
            routeCount: routes.length,
            endpointCount: endpoints.length,
            graphqlCount: graphql.length,
            hiddenParamCount: hiddenParams.length,
            surfaceCount: surfaces.length,
            gadgetCount: gadgets.length,
            enginesPresent: sortEngines([
                ...routes.flatMap((entry) => entry.enginesPresent || []),
                ...endpoints.flatMap((entry) => entry.enginesPresent || []),
                ...graphql.flatMap((entry) => entry.enginesPresent || []),
                ...hiddenParams.flatMap((entry) => entry.enginesPresent || []),
                ...surfaces.flatMap((entry) => entry.enginesPresent || []),
                ...gadgets.flatMap((entry) => entry.enginesPresent || [])
            ])
        },
        routes,
        endpoints,
        graphql,
        hiddenParams,
        surfaces,
        gadgets
    }
}

export default buildApiExplorer
