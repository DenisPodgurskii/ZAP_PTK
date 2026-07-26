import {
    buildRouteKey,
    buildRouteFamilyKey,
    normalizeEngineName,
    normalizeParamKey,
    splitRouteKey
} from "./canonicalize.js"
import { normalizeEvidenceRefs } from "./evidenceRefs.js"
import { getAllProModuleMetadataEntries } from "./proModuleMetadataCatalog.js"

export const MAX_RECOMMENDATIONS = 25
const MAX_EVIDENCE_REFS = 8
const MAX_SIGNALS = 12
const MAX_MATCHED_MODULES = 5
const MAX_GUIDANCE = 5
const MIN_MODULE_MATCH_SCORE = 35

const CONFIDENCE_RANK = Object.freeze({
    high: 3,
    medium: 2,
    low: 1
})

const METHOD_SENSITIVE_SURFACES = new Set([
    "file_upload",
    "graphql",
    "jwt_token",
    "cors_cross_origin",
    "realtime"
])

const STATIC_ASSET_RE = /\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp|avif|json|txt|xml)(?:[?#].*)?$/i
const OBJECT_PARAM_RE = /^(?:id|.*(?:id|uuid|guid)|user|user_id|userid|account|account_id|accountid|tenant|tenant_id|tenantid|org|org_id|orgid|workspace|workspace_id|project|project_id|order|order_id|invoice|invoice_id|customer|customer_id|role|admin)$/i
const TRANSPORT_PARAM_RE = /^(?:sid|eio|t|transport|polling|websocket|socket|namespace|callback|jsonp|_|cb|cache|cachebuster|timestamp|ts|nonce)$/i
const REDIRECT_PARAM_RE = /^(?:url|uri|redirect|redirect_uri|redirecturl|return|returnurl|return_url|next|continue|callback|callback_url|target|destination|dest|to|goto|relaystate)$/i
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"])
const JWT_RE = /\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/
const ENGINE_ORDER = Object.freeze(["DAST", "IAST", "SAST", "SCA"])

const SURFACE_DEFS = Object.freeze({
    file_upload: {
        title: "File upload attack path",
        aliases: ["upload", "file", "multipart", "filename", "attachment", "avatar", "import", "media", "filereader"],
        guidance: [
            "Review accepted file types and server-side validation.",
            "Check whether uploaded files are transformed, stored, or served back.",
            "Verify ownership checks around uploaded objects."
        ]
    },
    graphql: {
        title: "GraphQL attack path",
        aliases: ["graphql", "gql", "operationname", "root-field", "api", "schema"],
        guidance: [
            "Review exposed operations, variables, and authorization boundaries.",
            "Check whether introspection, batching, and deeply nested queries are allowed.",
            "Prioritize operations that touch user, tenant, or admin objects."
        ]
    },
    api_schema: {
        title: "API schema expansion path",
        aliases: ["openapi", "swagger", "api-docs", "schema", "spec", "endpoint"],
        guidance: [
            "Use the schema to enumerate endpoints, methods, parameters, and object types.",
            "Compare documented routes with observed traffic.",
            "Prioritize authenticated write actions and object-specific resources."
        ]
    },
    authz_object: {
        title: "Object authorization attack path",
        aliases: ["authz", "idor", "bola", "access_control", "object", "tenant", "account", "workspace", "admin", "role"],
        guidance: [
            "Review whether object identifiers can be accessed across users or tenants.",
            "Compare the same route with different sessions or roles.",
            "Prioritize write actions and high-value object types."
        ]
    },
    jwt_token: {
        title: "Token authentication attack path",
        aliases: ["jwt", "bearer", "token", "id_token", "access_token", "refresh_token", "oidc", "oauth", "session"],
        guidance: [
            "Review where tokens are stored and sent.",
            "Check whether token claims influence authorization decisions.",
            "Avoid exposing token values in notes or reports unless explicitly needed."
        ]
    },
    cors_cross_origin: {
        title: "Cross-origin trust-boundary path",
        aliases: ["cors", "origin", "cross-origin", "postmessage", "messageport", "broadcastchannel"],
        guidance: [
            "Review allowed origins and credential handling.",
            "Check whether cross-window messages validate origin and message shape.",
            "Treat CORS signals as contextual until confirmed with an exploit path."
        ]
    },
    realtime: {
        title: "Realtime API attack path",
        aliases: ["websocket", "socket.io", "eventsource", "sse", "webtransport", "webrtc", "realtime"],
        guidance: [
            "Review handshake, authentication, and channel authorization.",
            "Check whether realtime messages expose or mutate object-specific data.",
            "Prioritize channels that carry user, tenant, or admin state."
        ]
    },
    cloud_storage: {
        title: "Cloud storage attack path",
        aliases: ["s3", "gcs", "azure", "blob", "bucket", "object-storage", "signed-url", "presign"],
        guidance: [
            "Review signed URL scope, expiry, and object ownership.",
            "Check upload and download paths together.",
            "Prioritize routes that generate or consume object keys."
        ]
    },
    client_discovery: {
        title: "Client-side discovery path",
        aliases: ["sourcemap", "source-map", "debug", "stack", "client", "secret", "internal", "config"],
        guidance: [
            "Review client artifacts for hidden routes, flags, and sensitive configuration.",
            "Correlate discovered endpoints with observed traffic.",
            "Do not treat secret-looking client strings as valid credentials without verification."
        ]
    },
    dom_xss: {
        title: "Client-side execution path",
        aliases: ["dom", "xss", "html", "script", "innerhtml", "postmessage", "template"],
        guidance: [
            "Review source-to-sink paths and route-controlled rendering.",
            "Prioritize sinks reachable from URL, storage, referrer, or postMessage data.",
            "Confirm behavior with safe, scoped payloads only."
        ]
    },
    sql_injection: {
        title: "Database input attack path",
        aliases: ["sql", "database", "sqli", "websql"],
        guidance: [
            "Prioritize parameters that influence filtering, sorting, search, or IDs.",
            "Review error handling and response differences.",
            "Confirm behavior with safe, scoped checks."
        ]
    },
    command_injection: {
        title: "Command/process input attack path",
        aliases: ["command", "cmdi", "shell", "exec", "process"],
        guidance: [
            "Review parameters that influence file names, hosts, paths, or process options.",
            "Prioritize routes that trigger imports, exports, diagnostics, or integrations.",
            "Avoid destructive payloads and keep checks scoped."
        ]
    },
    open_redirect: {
        title: "Redirect/navigation attack path",
        aliases: ["redirect", "navigation", "location", "href", "window.open"],
        guidance: [
            "Review whether destinations are constrained to trusted origins.",
            "Check login, logout, callback, and return-url flows.",
            "Prefer allow-list verification over payload volume."
        ]
    }
})

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function stableHash(value) {
    const raw = String(value || "")
    let hash = 2166136261
    for (let i = 0; i < raw.length; i += 1) {
        hash ^= raw.charCodeAt(i)
        hash = Math.imul(hash, 16777619)
    }
    return (hash >>> 0).toString(16).padStart(8, "0")
}

function sanitizeLabel(value, { maxLength = 120 } = {}) {
    const raw = toNonEmptyString(value)
    if (!raw) return null
    const cleaned = raw
        .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi, "Bearer token")
        .replace(JWT_RE, "JWT-like value")
        .replace(/[?&][A-Za-z0-9_.:-]{1,60}=[^\s<>"']{4,}/g, "?param=value")
        .replace(/\s+/g, " ")
        .trim()
    return cleaned ? cleaned.slice(0, maxLength) : null
}

function normalizeRoute(routeKey) {
    const raw = toNonEmptyString(routeKey)
    if (!raw) return { routeKey: null, routeFamilyKey: null, path: null, method: null }
    const parts = splitRouteKey(raw)
    return {
        routeKey: raw,
        routeFamilyKey: buildRouteFamilyKey(raw),
        path: parts.pathTemplate || null,
        method: parts.method || null
    }
}

function isStaticRoute(routeKey) {
    const path = normalizeRoute(routeKey).path || ""
    return STATIC_ASSET_RE.test(path)
}

function normalizeParam(rawParam, fallback = "param:<none>") {
    const normalized = toNonEmptyString(rawParam)
    if (!normalized || normalized === "param:<none>" || normalized === "<none>") return fallback
    if (/^[a-z]+:/i.test(normalized)) return normalized
    return normalizeParamKey(normalized, "param")
}

function sortEngines(engines = []) {
    return Array.from(new Set((Array.isArray(engines) ? engines : [])
        .map((engine) => normalizeEngineName(engine))
        .filter(Boolean)))
        .sort((a, b) => {
            const aIdx = ENGINE_ORDER.indexOf(a)
            const bIdx = ENGINE_ORDER.indexOf(b)
            if (aIdx >= 0 && bIdx >= 0) return aIdx - bIdx
            if (aIdx >= 0) return -1
            if (bIdx >= 0) return 1
            return a.localeCompare(b)
        })
}

function normalizeSourceEngines(value, fallback = []) {
    const raw = (Array.isArray(value) ? value : [value]).filter(Boolean)
    const fallbackValues = Array.isArray(fallback) ? fallback : [fallback]
    return sortEngines(raw.length ? raw : fallbackValues)
}

function addEngineLoc(refs = [], engines = []) {
    const sourceEngines = normalizeSourceEngines(engines)
    if (!sourceEngines.length) return refs
    return (Array.isArray(refs) ? refs : []).map((ref) => {
        if (!ref || typeof ref !== "object") return ref
        return {
            ...ref,
            loc: {
                ...(ref.loc && typeof ref.loc === "object" ? ref.loc : {}),
                engine: sourceEngines[0]
            }
        }
    })
}

function paramNameFromKey(value) {
    const raw = toNonEmptyString(value)
    if (!raw) return null
    const idx = raw.indexOf(":")
    return idx >= 0 ? raw.slice(idx + 1) : raw
}

function isRealtimeRoute(routeKey) {
    const path = normalizeRoute(routeKey).path || ""
    return /\/(?:socket\.io|sockjs|ws|websocket|events|sse)(?:\/|$)/i.test(path)
}

function isObjectAuthzCandidate(rawName, routeKey = null) {
    const name = paramNameFromKey(rawName)
    if (!name || name === "<none>") return false
    if (TRANSPORT_PARAM_RE.test(name)) return false
    if (isRealtimeRoute(routeKey)) return false
    return OBJECT_PARAM_RE.test(name)
}

function isRedirectCandidate(rawName, routeKey = null) {
    const name = paramNameFromKey(rawName)
    if (name && REDIRECT_PARAM_RE.test(name)) return true
    const path = normalizeRoute(routeKey).path || ""
    return /\/(?:redirect|callback|oauth|sso|login|logout|return)(?:\/|$)/i.test(path)
}

function addEvidenceNote(existing, note) {
    const normalized = sanitizeLabel(note, { maxLength: 120 })
    if (!normalized) return
    existing.evidenceNoteKeys = existing.evidenceNoteKeys || new Set()
    existing.evidenceNotes = existing.evidenceNotes || []
    if (existing.evidenceNoteKeys.has(normalized)) return
    existing.evidenceNoteKeys.add(normalized)
    existing.evidenceNotes.push(normalized)
}

function addRecommendationSeed(map, seed = {}) {
    const surfaceType = toNonEmptyString(seed.surfaceType)
    const def = SURFACE_DEFS[surfaceType]
    if (!surfaceType || !def) return
    const route = normalizeRoute(seed.routeKey)
    if (route.routeKey && isStaticRoute(route.routeKey) && surfaceType !== "client_discovery") return
    const sourceEngines = normalizeSourceEngines(seed.sourceEngines, seed.sourceEngine)
    const evidenceRefs = normalizeEvidenceRefs(addEngineLoc(seed.evidenceRefs || [], sourceEngines), { maxRefs: MAX_EVIDENCE_REFS })
    if (!evidenceRefs.length) return
    const paramKey = normalizeParam(seed.paramKey || seed.rawParam)
    const routePart = METHOD_SENSITIVE_SURFACES.has(surfaceType)
        ? route.routeKey || route.routeFamilyKey || "-"
        : route.routeFamilyKey || route.routeKey || "-"
    const dedupeKey = [surfaceType, routePart, paramKey || "param:<none>"].join("|")
    const existing = map.get(dedupeKey) || {
        surfaceType,
        title: def.title,
        routeKey: route.routeKey,
        routeFamilyKey: route.routeFamilyKey,
        paramKey,
        evidenceRefs: [],
        signals: [],
        signalKeys: new Set(),
        sourceEngines: new Set(),
        evidenceNotes: [],
        evidenceNoteKeys: new Set(),
        score: 0
    }
    evidenceRefs.forEach((ref) => existing.evidenceRefs.push(ref))
    sourceEngines.forEach((engine) => existing.sourceEngines.add(engine))
    const code = toNonEmptyString(seed.code) || "SURFACE_SIGNAL"
    const label = sanitizeLabel(seed.label || code, { maxLength: 140 }) || code
    const signalKey = `${code}:${label}`
    if (!existing.signalKeys.has(signalKey)) {
        existing.signalKeys.add(signalKey)
        existing.signals.push({
            code,
            label,
            weight: Math.max(1, Math.min(100, Number(seed.weight || 10)))
        })
    }
    addEvidenceNote(existing, seed.evidenceNote || label)
    existing.score += Math.max(1, Math.min(100, Number(seed.weight || 10)))
    if (!existing.routeKey && route.routeKey) existing.routeKey = route.routeKey
    if (!existing.routeFamilyKey && route.routeFamilyKey) existing.routeFamilyKey = route.routeFamilyKey
    map.set(dedupeKey, existing)
}

function getHeaderValue(headers = [], name = "") {
    if (!Array.isArray(headers) || !name) return null
    const needle = String(name).toLowerCase()
    const match = headers.find((header) => String(header?.name || "").toLowerCase() === needle)
    return toNonEmptyString(match?.value)
}

function extractRawBody(rawRequest = "") {
    if (typeof rawRequest !== "string" || !rawRequest.length) return ""
    const splitCrlf = rawRequest.indexOf("\r\n\r\n")
    if (splitCrlf >= 0) return rawRequest.slice(splitCrlf + 4)
    const splitLf = rawRequest.indexOf("\n\n")
    if (splitLf >= 0) return rawRequest.slice(splitLf + 2)
    return rawRequest
}

function collectMultipartFieldSignals(body = "") {
    if (typeof body !== "string" || !body.length) return []
    const signals = []
    if (/Content-Disposition:\s*form-data/i.test(body)) {
        signals.push({ code: "MULTIPART_FORM_DATA", label: "multipart form-data part observed", weight: 25 })
    }
    if (/\bfilename\s*=/i.test(body)) {
        signals.push({ code: "FILE_FIELD_PRESENT", label: "filename attribute present", weight: 35 })
    }
    const fieldNames = new Set()
    const re = /\bname\s*=\s*["']([^"'\r\n]{1,80})["']/gi
    let match = re.exec(body)
    while (match) {
        const value = sanitizeLabel(match[1], { maxLength: 60 })
        if (value && !/^(?:file|blob|data)$/i.test(value)) fieldNames.add(value)
        match = re.exec(body)
    }
    Array.from(fieldNames).slice(0, 3).forEach((field) => {
        signals.push({ code: "FORM_FIELD_PRESENT", label: `form field present: ${field}`, weight: 10, paramKey: normalizeParamKey(field, "param") })
    })
    return signals
}

function collectRequestSeeds(scanResult, map) {
    const hostHint = scanResult?.host || null
    const sourceEngine = normalizeEngineName(scanResult?.engine) || "DAST"
    ;(Array.isArray(scanResult?.requests) ? scanResult.requests : []).forEach((record, index) => {
        const requestId = toNonEmptyString(record?.id) || `req-${index + 1}`
        const originalRequest = record?.original?.request || record?.request || {}
        const originalResponse = record?.original?.response || record?.response || {}
        const method = String(originalRequest?.method || "GET").toUpperCase()
        const url = originalRequest?.url || record?.url || record?.original?.ui_url || "/"
        const routeKey = normalizeRoute(record?.routeKey).routeKey
            || buildRouteKey({ url, method, host: hostHint })
        const evidenceRefs = [{ type: "request", id: requestId, loc: { method, path: normalizeRoute(routeKey).path || "/" } }]
        const requestHeaders = Array.isArray(originalRequest?.headers) ? originalRequest.headers : []
        const responseHeaders = Array.isArray(originalResponse?.headers) ? originalResponse.headers : []
        const contentType = String(getHeaderValue(requestHeaders, "content-type") || "").toLowerCase()
        const rawBody = extractRawBody(originalRequest?.raw || "")
        const requestHeaderText = requestHeaders.map((h) => `${h?.name || ""}:${h?.value || ""}`).join(" ")
        const responseHeaderText = responseHeaders.map((h) => `${h?.name || ""}:${h?.value || ""}`).join(" ")
        const combined = [
            url,
            contentType,
            rawBody.slice(0, 2048),
            requestHeaderText,
            responseHeaderText
        ].join(" ")
        if (/multipart\/form-data/i.test(contentType)) {
            addRecommendationSeed(map, { surfaceType: "file_upload", routeKey, evidenceRefs, sourceEngine, code: "MULTIPART_CONTENT_TYPE", label: "multipart/form-data request", evidenceNote: "Request used multipart form data", weight: 35 })
            collectMultipartFieldSignals(rawBody).forEach((signal) => {
                addRecommendationSeed(map, { surfaceType: "file_upload", routeKey, paramKey: signal.paramKey, evidenceRefs, sourceEngine, ...signal })
            })
        }
        if (method !== "GET" && /\b(upload|import|avatar|attachment|media|file|image|photo|document)\b/i.test(url)) {
            addRecommendationSeed(map, { surfaceType: "file_upload", routeKey, evidenceRefs, sourceEngine, code: "UPLOAD_ROUTE_NAME", label: "upload-like route name", evidenceNote: "Non-GET route name suggests upload or import behavior", weight: 20 })
        }
        if (/\/(?:graphql|gql)(?:[/?#]|$)/i.test(url) || /"operationName"\s*:|"query"\s*:/i.test(rawBody)) {
            addRecommendationSeed(map, { surfaceType: "graphql", routeKey, evidenceRefs, sourceEngine, code: "GRAPHQL_TRAFFIC", label: "GraphQL-like request observed", evidenceNote: "GraphQL-like traffic was captured", weight: 40 })
        }
        if (/\/(?:swagger|openapi|api-docs|swagger-ui)(?:[/?#.]|$)|openapi\.json|swagger\.json/i.test(url)) {
            addRecommendationSeed(map, { surfaceType: "api_schema", routeKey, evidenceRefs, sourceEngine, code: "API_SCHEMA_ROUTE", label: "API schema or docs route observed", evidenceNote: "API schema/documentation route was observed", weight: 45 })
        }
        if (/authorization\s*:\s*bearer/i.test(combined) || JWT_RE.test(combined) || /\b(?:access_token|id_token|refresh_token)\b/i.test(combined)) {
            addRecommendationSeed(map, { surfaceType: "jwt_token", routeKey, evidenceRefs, sourceEngine, code: "TOKEN_AUTH_SIGNAL", label: "Bearer or JWT-like token observed", evidenceNote: "Token-based authentication material was observed", weight: 35 })
        }
        if (/access-control-allow-origin|access-control-allow-credentials/i.test(responseHeaderText)) {
            addRecommendationSeed(map, { surfaceType: "cors_cross_origin", routeKey, evidenceRefs, sourceEngine, code: "CORS_RESPONSE_HEADER", label: "CORS response header observed", evidenceNote: "Response exposed CORS policy headers", weight: 30 })
        }
        if (/\b(?:websocket|socket\.io|eventsource|webtransport|wss?:\/\/)\b/i.test(combined)) {
            addRecommendationSeed(map, { surfaceType: "realtime", routeKey, evidenceRefs, sourceEngine, code: "REALTIME_SIGNAL", label: "realtime transport signal observed", evidenceNote: "Realtime transport traffic was captured", weight: 35 })
        }
        if (/\b(?:s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|presign|signed-url|signed_url|bucket)\b/i.test(combined)) {
            addRecommendationSeed(map, { surfaceType: "cloud_storage", routeKey, evidenceRefs, sourceEngine, code: "CLOUD_STORAGE_SIGNAL", label: "cloud storage or signed URL signal observed", evidenceNote: "Cloud storage or signed URL signal was observed", weight: 35 })
        }
    })
}

function collectObservationSeeds(context, map) {
    const fallbackEngine = normalizeEngineName(context?.scanResult?.engine) || null
    const observations = [
        ...(Array.isArray(context?.attackObservations) ? context.attackObservations : []),
        ...(Array.isArray(context?.passiveObservations) ? context.passiveObservations : [])
    ]
    observations.forEach((observation) => {
        const routeKey = observation?.routeKey || null
        const evidenceRefs = observation?.evidenceRefs || []
        const combined = [
            observation?.moduleId,
            observation?.ruleId,
            observation?.category,
            observation?.reconKind,
            observation?.uiSurface,
            observation?.responseText,
            observation?.rawParam,
            observation?.paramKey
        ].filter(Boolean).join(" ")
        const sourceEngine = normalizeEngineName(observation?.engine) || fallbackEngine
        const method = String(observation?.method || normalizeRoute(routeKey).method || "GET").toUpperCase()
        if (isObjectAuthzCandidate(observation?.rawParam || observation?.paramKey, routeKey)) {
            const isWrite = WRITE_METHODS.has(method)
            addRecommendationSeed(map, { surfaceType: "authz_object", routeKey, paramKey: observation?.paramKey, evidenceRefs, sourceEngine, code: isWrite ? "OBJECT_IDENTIFIER_WRITE" : "OBJECT_IDENTIFIER", label: isWrite ? "object identifier on write-capable route" : "object-like identifier observed", evidenceNote: isWrite ? "Object-like identifier appears on a write-capable route" : "Object-like identifier was observed", weight: isWrite ? 40 : 24 })
        }
        if (/\b(sql|database|sqli)\b/i.test(combined)) {
            addRecommendationSeed(map, { surfaceType: "sql_injection", routeKey, paramKey: observation?.paramKey, evidenceRefs, sourceEngine, code: "DATABASE_SIGNAL", label: "database-related signal observed", weight: 20 })
        }
        if (/\b(command|cmdi|shell|exec|process)\b/i.test(combined)) {
            addRecommendationSeed(map, { surfaceType: "command_injection", routeKey, paramKey: observation?.paramKey, evidenceRefs, sourceEngine, code: "COMMAND_SIGNAL", label: "command/process signal observed", weight: 20 })
        }
        if (isRedirectCandidate(observation?.rawParam || observation?.paramKey, routeKey)) {
            addRecommendationSeed(map, { surfaceType: "open_redirect", routeKey, paramKey: observation?.paramKey, evidenceRefs, sourceEngine, code: "REDIRECT_PARAM", label: "redirect-like parameter or route observed", evidenceNote: "Redirect-like parameter or route was observed", weight: 28 })
        }
    })
}

function collectExplorerSeeds(explorer, map) {
    ;(Array.isArray(explorer?.graphql) ? explorer.graphql : []).forEach((entry) => {
        addRecommendationSeed(map, { surfaceType: "graphql", routeKey: entry.routeKey, evidenceRefs: entry.evidenceRefs, sourceEngines: entry.enginesPresent, code: "GRAPHQL_EXPLORER", label: "GraphQL artifact in API explorer", evidenceNote: "Explorer identified GraphQL artifacts", weight: 50 })
    })
    ;(Array.isArray(explorer?.endpoints) ? explorer.endpoints : []).forEach((entry) => {
        const combined = [
            entry.path,
            ...(entry.contentTypes || []),
            ...(entry.paramNames || []),
            ...(entry.bodyKeys || []),
            ...(entry.discoveryTags || []),
            ...(entry.headerNames || [])
        ].join(" ")
        if (/multipart|upload|filename|avatar|attachment|file/i.test(combined)) {
            addRecommendationSeed(map, { surfaceType: "file_upload", routeKey: entry.routeKey, evidenceRefs: entry.evidenceRefs, sourceEngines: entry.enginesPresent, code: "UPLOAD_EXPLORER", label: "upload-like endpoint in API explorer", evidenceNote: "Explorer identified an upload-like endpoint", weight: 35 })
        }
        if (/authorization|bearer|jwt|token|session/i.test(combined)) {
            addRecommendationSeed(map, { surfaceType: "jwt_token", routeKey: entry.routeKey, evidenceRefs: entry.evidenceRefs, sourceEngines: entry.enginesPresent, code: "TOKEN_EXPLORER", label: "token/auth endpoint signal in API explorer", evidenceNote: "Explorer identified token or auth context", weight: 25 })
        }
        ;[...(entry.paramNames || []), ...(entry.bodyKeys || [])].forEach((name) => {
            if (isObjectAuthzCandidate(name, entry.routeKey)) {
                const method = String(entry.method || "").toUpperCase()
                const isWrite = WRITE_METHODS.has(method)
                addRecommendationSeed(map, { surfaceType: "authz_object", routeKey: entry.routeKey, paramKey: normalizeParamKey(name, "param"), evidenceRefs: entry.evidenceRefs, sourceEngines: entry.enginesPresent, code: isWrite ? "OBJECT_PARAM_WRITE_EXPLORER" : "OBJECT_PARAM_EXPLORER", label: isWrite ? "object-like input on write endpoint" : "object-like parameter in API explorer", evidenceNote: isWrite ? "Explorer found object-like input on a write endpoint" : "Explorer found object-like input", weight: isWrite ? 38 : 22 })
            }
        })
    })
    ;(Array.isArray(explorer?.hiddenParams) ? explorer.hiddenParams : []).forEach((entry) => {
        const surfaceType = isObjectAuthzCandidate(entry.paramName, entry.routeKey) ? "authz_object" : "client_discovery"
        addRecommendationSeed(map, { surfaceType, routeKey: entry.routeKey, paramKey: normalizeParamKey(entry.paramName, "param"), evidenceRefs: entry.evidenceRefs, sourceEngines: entry.enginesPresent, code: "HIDDEN_PARAM", label: "hidden parameter discovered in client code", evidenceNote: "Client-side code exposed a hidden parameter", weight: 25 })
    })
    ;(Array.isArray(explorer?.surfaces) ? explorer.surfaces : []).forEach((entry) => {
        const combined = [entry.surfaceType, entry.label, ...(entry.hintNames || [])].join(" ")
        const surfaceType = /source.?map|debug|secret|internal|config/i.test(combined) ? "client_discovery"
            : /dom|xss|html|script|template/i.test(combined) ? "dom_xss"
                : "client_discovery"
        addRecommendationSeed(map, { surfaceType, routeKey: entry.routeKey, evidenceRefs: entry.evidenceRefs, sourceEngines: entry.enginesPresent, code: "CLIENT_SURFACE", label: "client-side surface discovered", evidenceNote: "Explorer found client-side surface evidence", weight: 25 })
    })
    ;(Array.isArray(explorer?.gadgets) ? explorer.gadgets : []).forEach((entry) => {
        const combined = [entry.gadgetType, entry.label, ...(entry.hintNames || [])].join(" ")
        const surfaceType = /postmessage|messageport|broadcastchannel|origin/i.test(combined) ? "cors_cross_origin" : "dom_xss"
        addRecommendationSeed(map, { surfaceType, routeKey: entry.routeKey, evidenceRefs: entry.evidenceRefs, sourceEngines: entry.enginesPresent, code: "CLIENT_GADGET", label: "client-side gadget discovered", evidenceNote: "Explorer found client-side gadget evidence", weight: 30 })
    })
}

function collectObjectInventorySeeds(objectInventory, map) {
    ;(Array.isArray(objectInventory?.identifiers) ? objectInventory.identifiers : []).forEach((entry) => {
        if (!isObjectAuthzCandidate(entry?.name)) return
        const routeKeys = Array.isArray(entry.routeKeys) && entry.routeKeys.length ? entry.routeKeys : [null]
        routeKeys.slice(0, 3).forEach((routeKey) => {
            if (!isObjectAuthzCandidate(entry?.name, routeKey)) return
            addRecommendationSeed(map, { surfaceType: "authz_object", routeKey, paramKey: normalizeParamKey(entry.name, "param"), evidenceRefs: entry.evidenceRefs, sourceEngines: entry.enginesPresent || "DAST", code: "OBJECT_INVENTORY", label: "object identifier in inventory", evidenceNote: "Object inventory grouped this identifier across routes", weight: 35 })
        })
    })
}

function scoreConfidence(seed) {
    if (seed.score >= 80 || seed.signals.length >= 3) return "high"
    if (seed.score >= 40 || seed.signals.length >= 2) return "medium"
    return "low"
}

function moduleSearchText(moduleDef) {
    return [
        moduleDef.moduleId,
        moduleDef.name,
        moduleDef.category,
        moduleDef.vulnId,
        moduleDef.description,
        moduleDef.recommendationSummary,
        ...(Array.isArray(moduleDef.tags) ? moduleDef.tags : []),
        ...(Array.isArray(moduleDef.surfaceHints) ? moduleDef.surfaceHints : [])
    ].filter(Boolean).join(" ").toLowerCase()
}

function matchModules(surfaceType) {
    const def = SURFACE_DEFS[surfaceType]
    if (!def) return []
    return getAllProModuleMetadataEntries()
        .map((moduleDef) => {
            const reasons = []
            let score = 0
            if ((moduleDef.surfaceHints || []).includes(surfaceType)) {
                score += 70
                reasons.push(`surface:${surfaceType}`)
            }
            const text = moduleSearchText(moduleDef)
            ;(def.aliases || []).forEach((alias) => {
                const normalizedAlias = String(alias || "").toLowerCase()
                if (!normalizedAlias || !text.includes(normalizedAlias)) return
                score += Array.isArray(moduleDef.tags) && moduleDef.tags.map((tag) => String(tag).toLowerCase()).includes(normalizedAlias) ? 18 : 8
                reasons.push(`alias:${normalizedAlias}`)
            })
            if (score < MIN_MODULE_MATCH_SCORE) return null
            return {
                engine: moduleDef.engine,
                moduleId: moduleDef.moduleId,
                name: moduleDef.name,
                tier: moduleDef.tier,
                category: moduleDef.category,
                severity: moduleDef.severity,
                vulnId: moduleDef.vulnId,
                tags: Array.isArray(moduleDef.tags) ? moduleDef.tags.slice(0, 8) : [],
                description: moduleDef.description,
                recommendationSummary: moduleDef.recommendationSummary,
                links: moduleDef.links && typeof moduleDef.links === "object" ? { ...moduleDef.links } : {},
                surfaceHints: Array.isArray(moduleDef.surfaceHints) ? moduleDef.surfaceHints.slice() : [],
                matchScore: Math.min(100, score),
                matchReasons: Array.from(new Set(reasons)).slice(0, 8)
            }
        })
        .filter(Boolean)
        .sort((a, b) => {
            const scoreDelta = Number(b.matchScore || 0) - Number(a.matchScore || 0)
            if (scoreDelta !== 0) return scoreDelta
            const tierCmp = String(a.tier || "").localeCompare(String(b.tier || ""))
            if (tierCmp !== 0) return tierCmp
            const engineCmp = String(a.engine || "").localeCompare(String(b.engine || ""))
            if (engineCmp !== 0) return engineCmp
            return String(a.moduleId || "").localeCompare(String(b.moduleId || ""))
        })
        .slice(0, MAX_MATCHED_MODULES)
}

function buildProActions(matchedModules = []) {
    return matchedModules.slice(0, MAX_MATCHED_MODULES).map((moduleDef) => ({
        id: `${String(moduleDef.engine || "").toLowerCase()}_${moduleDef.moduleId}`,
        label: moduleDef.name || moduleDef.moduleId,
        status: moduleDef.tier === "free" ? "available" : moduleDef.tier === "pro" ? "locked" : "coming_soon",
        moduleIds: [moduleDef.moduleId].filter(Boolean)
    }))
}

function buildEvidenceSummary(seed, evidenceRefs = [], sourceEngines = []) {
    const route = normalizeRoute(seed.routeKey || seed.routeFamilyKey)
    const observations = [
        ...(Array.isArray(seed.evidenceNotes) ? seed.evidenceNotes : []),
        ...(Array.isArray(seed.signals) ? seed.signals.map((signal) => signal?.label || signal?.code) : [])
    ]
        .map((item) => sanitizeLabel(item, { maxLength: 120 }))
        .filter(Boolean)
    return {
        method: route.method || null,
        path: route.path || null,
        routeKey: seed.routeKey || null,
        routeFamilyKey: seed.routeFamilyKey || null,
        paramKey: seed.paramKey || "param:<none>",
        sourceEngines,
        evidenceCount: evidenceRefs.length,
        observations: Array.from(new Set(observations)).slice(0, 6)
    }
}

function normalizeSeed(seed) {
    const def = SURFACE_DEFS[seed.surfaceType]
    const evidenceRefs = normalizeEvidenceRefs(seed.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
    if (!def || !evidenceRefs.length) return null
    const confidence = scoreConfidence(seed)
    const matchedModules = matchModules(seed.surfaceType)
    const priority = Math.min(100, Math.max(1, Math.round(seed.score + (matchedModules[0]?.matchScore || 0) / 3 + evidenceRefs.length * 2)))
    const id = `rec_${seed.surfaceType}_${stableHash([seed.routeKey, seed.routeFamilyKey, seed.paramKey, seed.signals.map((s) => s.code).join(",")].join("|"))}`
    const sourceEngines = sortEngines([
        ...(seed.sourceEngines instanceof Set ? Array.from(seed.sourceEngines) : []),
        ...evidenceRefs.map((ref) => ref?.loc?.engine).filter(Boolean)
    ])
    return {
        id,
        surfaceType: seed.surfaceType,
        title: def.title,
        priority,
        confidence,
        sourceEngines,
        evidenceSummary: buildEvidenceSummary(seed, evidenceRefs, sourceEngines),
        routeKey: seed.routeKey || null,
        routeFamilyKey: seed.routeFamilyKey || null,
        paramKey: seed.paramKey || "param:<none>",
        evidenceRefs,
        signals: seed.signals.slice(0, MAX_SIGNALS).map((signal) => ({
            code: signal.code,
            label: signal.label,
            weight: Number(signal.weight || 0)
        })),
        freeGuidance: def.guidance.slice(0, MAX_GUIDANCE),
        matchedModules,
        proActions: buildProActions(matchedModules)
    }
}

export function buildAttackSurfaceRecommendations({
    scanResult = {},
    context = {},
    explorer = null,
    objectInventory = null
} = {}) {
    const map = new Map()
    collectRequestSeeds(scanResult, map)
    collectObservationSeeds(context, map)
    collectExplorerSeeds(explorer, map)
    collectObjectInventorySeeds(objectInventory, map)
    return Array.from(map.values())
        .map(normalizeSeed)
        .filter(Boolean)
        .sort((a, b) => {
            const priorityDelta = Number(b.priority || 0) - Number(a.priority || 0)
            if (priorityDelta !== 0) return priorityDelta
            const confidenceDelta = (CONFIDENCE_RANK[b.confidence] || 0) - (CONFIDENCE_RANK[a.confidence] || 0)
            if (confidenceDelta !== 0) return confidenceDelta
            const evidenceDelta = (b.evidenceRefs?.length || 0) - (a.evidenceRefs?.length || 0)
            if (evidenceDelta !== 0) return evidenceDelta
            const titleCmp = String(a.title || "").localeCompare(String(b.title || ""))
            if (titleCmp !== 0) return titleCmp
            const routeCmp = String(a.routeKey || "").localeCompare(String(b.routeKey || ""))
            if (routeCmp !== 0) return routeCmp
            const paramCmp = String(a.paramKey || "").localeCompare(String(b.paramKey || ""))
            if (paramCmp !== 0) return paramCmp
            return String(a.id || "").localeCompare(String(b.id || ""))
        })
        .slice(0, MAX_RECOMMENDATIONS)
}

export default buildAttackSurfaceRecommendations
