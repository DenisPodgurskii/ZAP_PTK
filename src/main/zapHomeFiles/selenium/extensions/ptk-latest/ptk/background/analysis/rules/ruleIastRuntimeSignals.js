import { buildRouteFamilyKey, buildRouteKey, normalizeParamKey, splitRouteKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const RULE_CODE = "R12_IAST_RUNTIME_SIGNALS"
const MAX_BUCKETS = 25
const MAX_CANDIDATES = 25
const MAX_EVIDENCE_REFS = 10
const MAX_DISCOVERY_BUCKETS = 50
const ALLOWED_BUCKETS = new Set([
    "client_execution",
    "navigation_and_route_control",
    "client_authz_and_state",
    "data_exposure_and_storage",
    "cross_context_messaging",
    "runtime_integrity_and_third_party"
])
const ROUTE_SOURCE_KINDS = new Set([
    "query",
    "hashquery",
    "hashroute",
    "clientroute",
    "historystate",
    "pathname",
    "pathsegment"
])
const STORAGE_SOURCE_KINDS = new Set([
    "cookie",
    "localstorage",
    "sessionstorage",
    "windowname",
    "referrer",
    "bodyparam",
    "jsonbodyfield",
    "formdatafield",
    "graphqlvariable",
    "apiresponsefield",
    "graphqlresponsefield"
])

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function toLowerLabel(value) {
    const normalized = toNonEmptyString(value)
    return normalized ? normalized.toLowerCase() : null
}

function normalizeDataKind(value) {
    return toLowerLabel(value)
}

function inferDataKind(entry = {}) {
    const explicit = normalizeDataKind(entry?.explicit)
    if (explicit && explicit !== "unknown") return explicit
    const haystack = [
        entry?.detectionReason,
        entry?.sourceKey,
        entry?.sourceName,
        entry?.storageKey,
        entry?.headerName,
        entry?.cookieName,
        entry?.paramKey,
        entry?.sinkId,
        entry?.valuePreview
    ]
        .map((value) => String(value || "").toLowerCase())
        .join(" ")
    if (!haystack) return null
    if (containsAny(haystack, ["jwt", "bearer", "auth_header", " id_token", " access_token", " refresh_token", "totp_tmp_token", "\"token\"", " token"])) {
        return "token"
    }
    if (containsAny(haystack, ["credential", "credentials"])) {
        return "credentials"
    }
    if (containsAny(haystack, ["password", "passwd", "passcode"])) {
        return "password"
    }
    if (containsAny(haystack, ["session"])) {
        return "session"
    }
    if (containsAny(haystack, ["secret", "api_key", "apikey"])) {
        return "secret"
    }
    if (containsAny(haystack, ["email", "@"])) {
        return "email"
    }
    if (containsAny(haystack, ["showversionnumber", "feature_flag", "featureflag", " flag"])) {
        return "feature_flag"
    }
    if (containsAny(haystack, ["version", "status", "config.application"])) {
        return "metadata"
    }
    return null
}

function normalizeTrustValue(value) {
    return toLowerLabel(value)
}

function normalizeSanitizerIds(values) {
    if (!Array.isArray(values)) return []
    const out = []
    const seen = new Set()
    values.forEach((entry) => {
        const raw = (
            entry && typeof entry === "object"
                ? (entry.id || entry.name || entry.label || entry.code)
                : entry
        )
        const normalized = toNonEmptyString(raw)
        if (!normalized) return
        const key = normalized.toLowerCase()
        if (seen.has(key)) return
        seen.add(key)
        out.push(normalized)
    })
    return out
}

function addSignal(signals, code, value, weight = null) {
    const signal = { code, value }
    if (Number.isFinite(Number(weight))) {
        signal.weight = Number(weight)
    }
    signals.push(signal)
}

function containsAny(haystack, needles = []) {
    const normalized = String(haystack || "").toLowerCase()
    return needles.some((needle) => normalized.includes(String(needle).toLowerCase()))
}

function severityRank(severity) {
    switch (String(severity || "").toLowerCase()) {
    case "critical":
        return 5
    case "high":
        return 4
    case "medium":
        return 3
    case "low":
        return 2
    case "info":
        return 1
    default:
        return 0
    }
}

function bucketWeight(bucket) {
    switch (bucket) {
    case "client_execution":
        return 24
    case "cross_context_messaging":
        return 20
    case "navigation_and_route_control":
        return 18
    case "client_authz_and_state":
        return 18
    case "data_exposure_and_storage":
        return 16
    case "runtime_integrity_and_third_party":
        return 14
    default:
        return 10
    }
}

function normalizeLegacyFamily(entry = {}) {
    const explicit = toLowerLabel(entry?.signalFamily)
    if (explicit) return explicit
    const sinkId = String(entry?.sinkId || "").toLowerCase()
    const sourceKind = String(entry?.sourceKind || "").toLowerCase()
    const category = String(entry?.category || "").toLowerCase()
    const reason = String(entry?.detectionReason || entry?.signalCode || entry?.primaryReason || "").toLowerCase()
    const primaryClass = String(entry?.primaryClass || "").toLowerCase()
    if (sinkId.startsWith("storage.") || containsAny(reason, ["token", "jwt", "auth_header"])) {
        return "auth_signal"
    }
    if (sinkId.startsWith("postmessage") || sinkId.startsWith("channel.") || sourceKind === "postmessage") {
        return "message_boundary"
    }
    if (sinkId.startsWith("nav.") || category === "open_redirect" || category === "link") {
        return "navigation_control"
    }
    if (sinkId.startsWith("code.") || sinkId === "document.write" || sinkId.startsWith("dom.") || category === "xss") {
        return "client_execution"
    }
    if (primaryClass === "policy_violation") {
        return "policy_violation"
    }
    return "client_runtime"
}

function sourceLocationForKind(kind) {
    switch (String(kind || "").toLowerCase()) {
    case "query":
        return "query"
    case "hashquery":
        return "hash"
    case "hashroute":
    case "clientroute":
    case "historystate":
    case "pathname":
    case "pathsegment":
        return "route"
    case "cookie":
        return "cookie"
    case "localstorage":
    case "sessionstorage":
        return "storage"
    case "postmessage":
        return "message"
    case "inline":
        return "form"
    case "bodyparam":
    case "jsonbodyfield":
    case "formdatafield":
    case "graphqlvariable":
        return "body"
    case "apiresponsefield":
    case "graphqlresponsefield":
        return "response"
    case "referrer":
        return "header"
    default:
        return "param"
    }
}

function extractSourceName(entry = {}) {
    const sourceKind = String(entry?.sourceKind || "").trim()
    const sourceKey = toNonEmptyString(entry?.sourceKey)
    const direct = (
        toNonEmptyString(entry?.storageKey)
        || toNonEmptyString(entry?.cookieName)
        || toNonEmptyString(entry?.headerName)
        || toNonEmptyString(entry?.attribute)
    )
    if (direct) {
        return {
            location: sourceLocationForKind(sourceKind),
            name: direct
        }
    }
    if (!sourceKey) {
        return {
            location: sourceLocationForKind(sourceKind),
            name: "<none>"
        }
    }
    const raw = String(sourceKey)
    const stripPrefix = (prefix) => raw.startsWith(prefix) ? raw.slice(prefix.length) : null
    const normalizedKind = sourceKind.toLowerCase()
    if (normalizedKind === "query") {
        return { location: "query", name: stripPrefix("query:") || raw }
    }
    if (normalizedKind === "hashquery") {
        return { location: "hash", name: stripPrefix("hash:param:") || raw }
    }
    if (normalizedKind === "hashroute" || normalizedKind === "clientroute" || normalizedKind === "historystate") {
        return { location: "route", name: stripPrefix("hash:route") || raw }
    }
    if (normalizedKind === "cookie") {
        return { location: "cookie", name: stripPrefix("cookie:") || raw }
    }
    if (normalizedKind === "localstorage") {
        return { location: "storage", name: stripPrefix("localStorage:") || raw }
    }
    if (normalizedKind === "sessionstorage") {
        return { location: "storage", name: stripPrefix("sessionStorage:") || raw }
    }
    if (normalizedKind === "inline") {
        return { location: "form", name: stripPrefix("inline:") || raw }
    }
    if (normalizedKind === "postmessage") {
        return { location: "message", name: raw.replace(/^postMessage:/, "") || "postMessage" }
    }
    if (normalizedKind === "apiresponsefield") {
        return { location: "response", name: stripPrefix("response:json:") || raw }
    }
    if (normalizedKind === "graphqlresponsefield") {
        return { location: "response", name: stripPrefix("graphql:response:") || raw }
    }
    return {
        location: sourceLocationForKind(sourceKind),
        name: raw
    }
}

function normalizeRuntimeEventRefs(entry = {}, routeKey = "unknown-host|GET|/") {
    const routeParts = splitRouteKey(routeKey)
    const source = extractSourceName({
        sourceKind: entry?.sourceKind,
        sourceKey: entry?.sourceKey,
        storageKey: entry?.storageKey,
        cookieName: entry?.cookieName,
        headerName: entry?.headerName,
        attribute: entry?.attribute
    })
    const descriptor = deriveBucketDescriptor({
        signalFamily: entry?.signalFamily,
        sinkId: entry?.sinkId,
        sourceKind: entry?.sourceKind,
        category: entry?.category,
        detectionReason: entry?.detection?.reason || entry?.signalCode,
        primaryClass: entry?.primaryClass,
        trustLevel: entry?.trust?.level,
        moduleId: entry?.moduleId,
        ruleId: entry?.ruleId
    })
    const paramLabel = (
        toNonEmptyString(entry?.sourceName)
        || toNonEmptyString(entry?.sourceKey)
        || 
        (source?.name && source.name !== "<none>" ? source.name : null)
        || toNonEmptyString(entry?.sinkId)
        || toNonEmptyString(entry?.signalCode)
        || null
    )
    return normalizeEvidenceRefs([
        entry?.evidenceRef || null,
        entry?.id ? {
            type: entry.kind === "finding" ? "finding" : "runtimeEvent",
            id: entry.id,
            loc: {
                method: entry?.method || routeParts.method || "GET",
                path: routeParts.pathTemplate || "/",
                route: routeKey,
                kind: entry?.bucket || entry?.legacyFamily || descriptor.bucket || descriptor.legacyFamily || "iast_runtime",
                module: entry?.moduleId || null,
                rule: entry?.ruleId || null,
                param: paramLabel
            }
        } : null,
        ...(Array.isArray(entry?.evidenceRefs) ? entry.evidenceRefs : [])
    ], { maxRefs: MAX_EVIDENCE_REFS })
}

function getIastEvidencePayload(finding = {}) {
    const evidence = finding?.evidence
    if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) return {}
    if (evidence.iast && typeof evidence.iast === "object" && !Array.isArray(evidence.iast)) {
        return evidence.iast
    }
    return evidence
}

function getPrimaryIastSource(evidence = {}) {
    const sources = Array.isArray(evidence?.sources) ? evidence.sources : []
    for (const source of sources) {
        if (!source || typeof source !== "object") continue
        const sourceKind = toNonEmptyString(source?.sourceKind || source?.kind)
        const sourceKey = toNonEmptyString(source?.key || source?.source || source?.sourceId)
        if (sourceKind || sourceKey) {
            return source
        }
    }
    return null
}

function deriveBucketDescriptor(entry = {}) {
    const sinkId = String(entry?.sinkId || "").toLowerCase()
    const sourceKind = String(entry?.sourceKind || "").toLowerCase()
    const category = String(entry?.category || "").toLowerCase()
    const reason = String(entry?.detectionReason || entry?.signalCode || entry?.primaryReason || "").toLowerCase()
    const primaryClass = String(entry?.primaryClass || "").toLowerCase()
    const trustLevel = String(entry?.trustLevel || "").toLowerCase()
    const moduleLabel = `${String(entry?.moduleId || "").toLowerCase()} ${String(entry?.ruleId || "").toLowerCase()}`
    const legacyFamily = normalizeLegacyFamily(entry)

    if (sinkId.startsWith("postmessage") || sinkId.startsWith("channel.") || sourceKind === "postmessage") {
        let subtype = "postmessage_flow"
        if (sinkId.startsWith("channel.broadcast")) subtype = "broadcast_channel_flow"
        else if (sinkId.startsWith("channel.messageport")) subtype = "message_port_flow"
        else if (containsAny(sinkId, ["crossorigin", "anyorigin"])) subtype = "cross_origin_message_flow"
        return { bucket: "cross_context_messaging", subtype, legacyFamily }
    }

    if (
        legacyFamily === "client_execution"
        || sinkId.startsWith("code.")
        || sinkId === "document.write"
        || sinkId.startsWith("dom.")
        || category === "xss"
    ) {
        let subtype = "dom_execution"
        if (containsAny(sinkId, ["eval", "function", "timer"])) subtype = "dynamic_code_execution"
        else if (containsAny(sinkId, ["domparser", "createcontextualfragment"])) subtype = "html_parser_execution"
        else if (containsAny(sinkId, ["sethtmlunsafe", "innerhtml", "outerhtml", "insertadjacenthtml", "document.write"])) subtype = "html_sink_execution"
        return { bucket: "client_execution", subtype, legacyFamily }
    }

    if (
        trustLevel === "third_party"
        || containsAny(reason, ["prototype", "pollution", "supply chain", "third_party", "third-party"])
        || containsAny(moduleLabel, ["prototype", "pollution"])
        || sinkId.startsWith("runtime.prototype.")
        || sinkId.startsWith("script.element.src")
        || sinkId.startsWith("worker.")
        || sinkId.startsWith("http.fetch.url")
        || sinkId.startsWith("http.xhr.open")
        || sinkId.startsWith("http.image.src")
        || sinkId.startsWith("realtime.websocket.")
    ) {
        let subtype = "runtime_integrity"
        if (containsAny(reason, ["prototype", "pollution"]) || containsAny(moduleLabel, ["prototype", "pollution"]) || sinkId.startsWith("runtime.prototype.")) {
            subtype = "prototype_pollution_impact"
        } else if (trustLevel === "third_party" || sinkId.startsWith("script.element.src")) {
            subtype = "third_party_runtime"
        } else if (sinkId.startsWith("worker.")) {
            subtype = "worker_bootstrap"
        } else if (sinkId.startsWith("realtime.websocket.")) {
            subtype = "realtime_runtime"
        }
        return { bucket: "runtime_integrity_and_third_party", subtype, legacyFamily }
    }

    if (
        legacyFamily === "auth_signal"
        && (
            sinkId === "http.xhr.setrequestheader"
            || sinkId === "http.fetch.headers"
            || containsAny(reason, ["auth_header", "authorization", "bearer", "session"])
        )
    ) {
        let subtype = "client_state_assumption"
        if (containsAny(reason, ["auth_header", "authorization", "bearer"])) subtype = "session_material_use"
        else if (containsAny(reason, ["session"])) subtype = "session_state_signal"
        return { bucket: "client_authz_and_state", subtype, legacyFamily }
    }

    if (
        sinkId === "client.json.parse"
        || sinkId === "client.json.stringify"
        || sinkId.startsWith("storage.")
        || STORAGE_SOURCE_KINDS.has(sourceKind)
        || containsAny(reason, ["token", "jwt", "secret", "storage", "cookie", "header leak", "data exposure"])
    ) {
        let subtype = "data_exposure"
        if (sinkId === "client.json.parse" || sinkId === "client.json.stringify") {
            subtype = "client_data_parsing"
        }
        if (sinkId.startsWith("storage.") || ["cookie", "localstorage", "sessionstorage"].includes(sourceKind)) {
            subtype = "storage_state"
        }
        if (containsAny(reason, ["token", "jwt", "cookie"])) {
            subtype = "credential_or_token_exposure"
        }
        return { bucket: "data_exposure_and_storage", subtype, legacyFamily }
    }

    if (
        legacyFamily === "auth_signal"
        || legacyFamily === "policy_violation"
        || primaryClass === "policy_violation"
        || containsAny(reason, ["auth", "role", "tenant", "admin", "flag", "policy", "guard", "privilege", "forbidden", "unauthorized"])
        || containsAny(moduleLabel, ["feature", "role", "tenant", "policy", "auth", "admin"])
    ) {
        let subtype = "client_state_assumption"
        if (containsAny(reason, ["feature", "flag"])) subtype = "feature_flag_state"
        else if (containsAny(reason, ["role", "admin", "tenant", "privilege"])) subtype = "privileged_state_signal"
        else if (primaryClass === "policy_violation" || legacyFamily === "policy_violation") subtype = "policy_violation"
        return { bucket: "client_authz_and_state", subtype, legacyFamily }
    }

    if (
        legacyFamily === "navigation_control"
        || sinkId.startsWith("nav.")
        || category === "open_redirect"
        || category === "link"
        || containsAny(reason, ["route_guard", "client_route", "forced_browse", "navigation_control", "redirect", "route_control"])
    ) {
        let subtype = "navigation_control"
        if (containsAny(reason, ["route_guard", "client_route", "forced_browse", "route_control"])) subtype = "route_control"
        if (containsAny(sinkId, [".javascript", ".data"])) subtype = "dangerous_scheme_navigation"
        if (containsAny(reason, ["route_guard", "client_route", "forced_browse"])) subtype = "route_guard_signal"
        return { bucket: "navigation_and_route_control", subtype, legacyFamily }
    }

    return {
        bucket: ALLOWED_BUCKETS.has(legacyFamily) ? legacyFamily : "runtime_integrity_and_third_party",
        subtype: "runtime_signal",
        legacyFamily
    }
}

function normalizeRuntimeEventInput(event = {}, hostHint = null) {
    if (!event || typeof event !== "object") return null
    const hasMeaningfulSignal = Boolean(
        toNonEmptyString(event?.signalFamily)
        || toNonEmptyString(event?.sinkId)
        || toNonEmptyString(event?.sourceKind)
        || toNonEmptyString(event?.signalCode)
        || toNonEmptyString(event?.category)
        || toNonEmptyString(event?.findingId)
    )
    if (!hasMeaningfulSignal) return null
    const url = toNonEmptyString(event?.url || event?.location?.url || event?.routing?.runtimeUrl || event?.routing?.url)
    const method = toNonEmptyString(event?.method || event?.location?.method) || "GET"
    const routeKey = buildRouteKey({
        url,
        method,
        host: hostHint
    })
    const source = extractSourceName(event)
    const descriptor = deriveBucketDescriptor({
        signalFamily: event?.signalFamily,
        sinkId: event?.sinkId,
        sourceKind: event?.sourceKind,
        category: event?.category,
        detectionReason: event?.detection?.reason || event?.signalCode,
        primaryClass: event?.primaryClass,
        trustLevel: event?.trust?.level,
        moduleId: event?.moduleId,
        ruleId: event?.ruleId
    })
    return {
        id: toNonEmptyString(event?.id) || `runtime:${routeKey}:${event?.sinkId || "sink"}`,
        uniqueKey: toNonEmptyString(event?.findingId) ? `finding:${String(event.findingId)}` : `runtime:${toNonEmptyString(event?.eventKey) || toNonEmptyString(event?.id) || routeKey}`,
        kind: "runtimeEvent",
        routeKey,
        routeFamilyKey: buildRouteFamilyKey(routeKey),
        paramKey: normalizeParamKey(source.name || "<none>", source.location || "param"),
        sourceKind: toNonEmptyString(event?.sourceKind),
        sourceName: source?.name,
        sourceLocation: source?.location,
        sourceKey: toNonEmptyString(event?.sourceKey),
        storageKey: toNonEmptyString(event?.storageKey),
        cookieName: toNonEmptyString(event?.cookieName),
        headerName: toNonEmptyString(event?.headerName),
        attribute: toNonEmptyString(event?.attribute),
        moduleId: toNonEmptyString(event?.moduleId),
        ruleId: toNonEmptyString(event?.ruleId),
        bucket: descriptor.bucket,
        subtype: descriptor.subtype,
        legacyFamily: descriptor.legacyFamily,
        primarySink: toNonEmptyString(event?.sinkId),
        primaryReason: toNonEmptyString(event?.detection?.reason || event?.signalCode),
        severity: String(event?.severity || "low").toLowerCase(),
        crossOrigin: event?.isCrossOrigin === true || String(event?.trust?.level || "").toLowerCase() === "third_party",
        routeControlled: ROUTE_SOURCE_KINDS.has(String(event?.sourceKind || "").toLowerCase()),
        sanitizedCount: Array.isArray(event?.sanitizers) ? event.sanitizers.length : 0,
        sanitizerIds: normalizeSanitizerIds(event?.sanitizers),
        thirdParty: String(event?.trust?.level || "").toLowerCase() === "third_party",
        trustLevel: normalizeTrustValue(event?.trust?.level),
        trustDecision: normalizeTrustValue(event?.trust?.decision),
        authLike: descriptor.bucket === "client_authz_and_state",
        dataKind: inferDataKind({
            explicit: event?.detection?.dataKind,
            detectionReason: event?.detection?.reason || event?.signalCode,
            sourceKey: event?.sourceKey,
            sourceName: source?.name,
            storageKey: event?.storageKey,
            headerName: event?.headerName,
            cookieName: event?.cookieName,
            paramKey: normalizeParamKey(source.name || "<none>", source.location || "param"),
            sinkId: event?.sinkId,
            valuePreview: event?.detection?.details?.valuePreview
        }),
        findingId: toNonEmptyString(event?.findingId),
        hasFinding: Boolean(event?.findingId),
        hasRuntimeEvent: true,
        confidence: Number.isFinite(Number(event?.confidence)) ? Number(event.confidence) : null,
        evidenceRefs: normalizeRuntimeEventRefs(event, routeKey)
    }
}

function normalizeFindingInput(finding = {}, hostHint = null) {
    if (!finding || typeof finding !== "object") return null
    if (String(finding?.engine || "").toUpperCase() !== "IAST") return null
    const evidence = getIastEvidencePayload(finding)
    const primarySource = getPrimaryIastSource(evidence)
    const hasMeaningfulSignal = Boolean(
        toNonEmptyString(evidence?.sinkId || finding?.sinkId)
        || toNonEmptyString(evidence?.sourceKind || primarySource?.sourceKind || primarySource?.kind)
        || toNonEmptyString(evidence?.primaryClass)
        || toNonEmptyString(evidence?.detection?.reason)
        || toNonEmptyString(finding?.ruleId)
        || toNonEmptyString(finding?.moduleId)
        || toNonEmptyString(finding?.category)
    )
    if (!hasMeaningfulSignal) return null
    const context = evidence?.context && typeof evidence.context === "object" ? evidence.context : {}
    const sinkContext = evidence?.sinkContext && typeof evidence.sinkContext === "object" ? evidence.sinkContext : {}
    const routing = evidence?.routing && typeof evidence.routing === "object" ? evidence.routing : {}
    const url = toNonEmptyString(finding?.location?.url || finding?.location?.runtimeUrl || routing?.runtimeUrl || routing?.url || context?.url || context?.location)
    const method = toNonEmptyString(finding?.location?.method || evidence?.operation?.method || context?.method) || "GET"
    const routeKey = buildRouteKey({
        url,
        method,
        host: hostHint
    })
    const source = extractSourceName({
        sourceKind: evidence?.sourceKind || primarySource?.sourceKind || primarySource?.kind,
        sourceKey: (
            evidence?.sourceKey
            || evidence?.primarySource?.key
            || evidence?.primarySource?.source
            || primarySource?.key
            || primarySource?.source
            || primarySource?.sourceId
            || evidence?.sourceId
            || evidence?.taintSource
        ),
        storageKey: context?.storageKey || sinkContext?.storageKey || context?.key,
        cookieName: context?.cookieName || sinkContext?.cookieName,
        headerName: context?.headerName || sinkContext?.headerName,
        attribute: context?.attribute || sinkContext?.attribute
    })
    const descriptor = deriveBucketDescriptor({
        sinkId: evidence?.sinkId || finding?.sinkId,
        sourceKind: evidence?.sourceKind || primarySource?.sourceKind || primarySource?.kind,
        category: finding?.category,
        detectionReason: evidence?.detection?.reason || finding?.ruleId,
        primaryClass: evidence?.primaryClass,
        trustLevel: evidence?.trust?.level,
        moduleId: finding?.moduleId,
        ruleId: finding?.ruleId
    })
    const sanitizerObserved = Array.isArray(context?.sanitizerObserved) ? context.sanitizerObserved : []
    const evidenceRef = toNonEmptyString(finding?.id) ? {
        type: "finding",
        id: finding.id,
        loc: {
            module: finding?.moduleId || null,
            rule: finding?.ruleId || null,
            title: finding?.title || finding?.ruleName || null,
            severity: finding?.severity || null,
            method
        }
    } : null
    return {
        id: toNonEmptyString(finding?.id) || `finding:${routeKey}:${finding?.ruleId || "rule"}`,
        uniqueKey: `finding:${toNonEmptyString(finding?.id) || `${routeKey}:${finding?.ruleId || "rule"}`}`,
        kind: "finding",
        routeKey,
        routeFamilyKey: buildRouteFamilyKey(routeKey),
        paramKey: normalizeParamKey(source.name || "<none>", source.location || "param"),
        sourceKind: toNonEmptyString(evidence?.sourceKind || primarySource?.sourceKind || primarySource?.kind),
        sourceName: source?.name,
        sourceLocation: source?.location,
        sourceKey: toNonEmptyString(
            evidence?.sourceKey
            || evidence?.primarySource?.key
            || evidence?.primarySource?.source
            || primarySource?.key
            || primarySource?.source
            || primarySource?.sourceId
            || evidence?.sourceId
            || evidence?.taintSource
        ),
        storageKey: toNonEmptyString(context?.storageKey || sinkContext?.storageKey || context?.key),
        cookieName: toNonEmptyString(context?.cookieName || sinkContext?.cookieName),
        headerName: toNonEmptyString(context?.headerName || sinkContext?.headerName),
        attribute: toNonEmptyString(context?.attribute || sinkContext?.attribute),
        moduleId: toNonEmptyString(finding?.moduleId),
        ruleId: toNonEmptyString(finding?.ruleId),
        bucket: descriptor.bucket,
        subtype: descriptor.subtype,
        legacyFamily: descriptor.legacyFamily,
        primarySink: toNonEmptyString(evidence?.sinkId || finding?.sinkId),
        primaryReason: toNonEmptyString(evidence?.detection?.reason || finding?.ruleId),
        severity: String(finding?.severity || "low").toLowerCase(),
        crossOrigin: context?.isCrossOrigin === true || evidence?.networkTarget?.isCrossOrigin === true || String(evidence?.trust?.level || "").toLowerCase() === "third_party",
        routeControlled: ROUTE_SOURCE_KINDS.has(String(evidence?.sourceKind || "").toLowerCase()),
        sanitizedCount: sanitizerObserved.length,
        sanitizerIds: normalizeSanitizerIds(sanitizerObserved),
        thirdParty: String(evidence?.trust?.level || "").toLowerCase() === "third_party",
        trustLevel: normalizeTrustValue(evidence?.trust?.level),
        trustDecision: normalizeTrustValue(evidence?.trust?.decision),
        authLike: descriptor.bucket === "client_authz_and_state",
        dataKind: inferDataKind({
            explicit: evidence?.detection?.dataKind,
            detectionReason: evidence?.detection?.reason || finding?.ruleId,
            sourceKey: (
                evidence?.sourceKey
                || evidence?.primarySource?.key
                || evidence?.primarySource?.source
                || primarySource?.key
                || primarySource?.source
                || primarySource?.sourceId
                || evidence?.sourceId
                || evidence?.taintSource
            ),
            sourceName: source?.name,
            storageKey: context?.storageKey || sinkContext?.storageKey || context?.key,
            headerName: context?.headerName || sinkContext?.headerName,
            cookieName: context?.cookieName || sinkContext?.cookieName,
            paramKey: normalizeParamKey(source.name || "<none>", source.location || "param"),
            sinkId: evidence?.sinkId || finding?.sinkId,
            valuePreview: context?.valuePreview || sinkContext?.valuePreview || evidence?.detection?.details?.valuePreview
        }),
        findingId: toNonEmptyString(finding?.id),
        hasFinding: true,
        hasRuntimeEvent: false,
        confidence: Number.isFinite(Number(finding?.confidence)) ? Number(finding.confidence) : null,
        evidenceRef,
        evidenceRefs: normalizeRuntimeEventRefs({
            kind: "finding",
            id: finding?.id,
            method,
            bucket: descriptor.bucket,
            evidenceRefs: [evidenceRef]
        }, routeKey)
    }
}

function buildBucketInputList(scanResult = {}, hostHint = null) {
    const inputs = []
    const runtimeEvents = Array.isArray(scanResult?.runtimeEvents) ? scanResult.runtimeEvents : []
    runtimeEvents.forEach((event) => {
        const normalized = normalizeRuntimeEventInput(event, hostHint)
        if (normalized) inputs.push(normalized)
    })
    const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
    findings.forEach((finding) => {
        const normalized = normalizeFindingInput(finding, hostHint)
        if (normalized) inputs.push(normalized)
    })
    return inputs
}

function bucketPatternTitle(bucket = {}, routeParts = {}) {
    const suffix = `${routeParts.method || "GET"} ${routeParts.pathTemplate || "/"}`
    switch (bucket.bucket) {
    case "client_execution":
        return `IAST client execution bucket on ${suffix}`
    case "navigation_and_route_control":
        return `IAST navigation and route-control bucket on ${suffix}`
    case "client_authz_and_state":
        return `IAST client authz/state bucket on ${suffix}`
    case "data_exposure_and_storage":
        return `IAST data exposure and storage bucket on ${suffix}`
    case "cross_context_messaging":
        return `IAST cross-context messaging bucket on ${suffix}`
    case "runtime_integrity_and_third_party":
        return `IAST runtime integrity / third-party bucket on ${suffix}`
    default:
        return `IAST runtime bucket on ${suffix}`
    }
}

function bucketCandidateTitle(bucket = {}, routeParts = {}) {
    const suffix = `${routeParts.method || "GET"} ${routeParts.pathTemplate || "/"}`
    switch (bucket.bucket) {
    case "client_execution":
        return `Validate client-side execution reachability on ${suffix}`
    case "navigation_and_route_control":
        return `Validate client-side navigation and route control on ${suffix}`
    case "client_authz_and_state":
        return `Validate client-side authz and state assumptions on ${suffix}`
    case "data_exposure_and_storage":
        return `Validate client-side data exposure and storage handling on ${suffix}`
    case "cross_context_messaging":
        return `Validate cross-context messaging trust boundaries on ${suffix}`
    case "runtime_integrity_and_third_party":
        return `Validate runtime integrity and third-party trust on ${suffix}`
    default:
        return `Validate IAST runtime bucket on ${suffix}`
    }
}

function bucketCandidateType(bucket = {}) {
    return bucket.bucket === "client_authz_and_state" ? "AUTHZ_INCONSISTENCY" : "RUNTIME_ANOMALY"
}

function buildBucketSignals(bucket = {}) {
    const signals = []
    addSignal(signals, "IAST_RUNTIME_SIGNAL", bucket.bucket, 8)
    addSignal(signals, "IAST_BUCKET", bucket.bucket, 6)
    if (bucket.subtypes.length) {
        addSignal(signals, "IAST_SUBTYPE", bucket.subtypes[0], 6)
    }
    switch (bucket.bucket) {
    case "client_execution":
        addSignal(signals, "CLIENT_EXECUTION_SINK", bucket.primarySink || "dom", 22)
        break
    case "navigation_and_route_control":
        addSignal(signals, "CLIENT_NAV_SINK", bucket.primarySink || "navigation", 16)
        break
    case "client_authz_and_state":
        addSignal(signals, "AUTH_SESSION_SIGNAL", bucket.primaryReason || "client_auth_signal", 12)
        break
    case "data_exposure_and_storage":
        addSignal(signals, "DATA_EXPOSURE_SIGNAL", bucket.primarySink || bucket.primaryReason || "storage", 14)
        break
    case "cross_context_messaging":
        addSignal(signals, "MESSAGE_TRUST_BOUNDARY", bucket.primarySink || "postmessage", 18)
        break
    case "runtime_integrity_and_third_party":
        if (bucket.thirdParty) {
            addSignal(signals, "THIRD_PARTY_RUNTIME_RISK", bucket.primarySink || "third_party", 14)
        } else {
            addSignal(signals, "CLIENT_RUNTIME_REVIEW", bucket.primarySink || "runtime", 10)
        }
        break
    default:
        addSignal(signals, "CLIENT_RUNTIME_REVIEW", bucket.primarySink || "runtime", 10)
        break
    }
    if (bucket.crossOrigin) {
        addSignal(signals, "TRUST_BOUNDARY_CROSS_ORIGIN", true, 14)
    }
    if (bucket.routeControlled) {
        addSignal(signals, "ROUTE_CONTROLLED_SOURCE", bucket.sourceKinds[0] || "route", 10)
    }
    if (bucket.sanitizedCount > 0) {
        addSignal(signals, "SANITIZED_FLOW_REVIEW", bucket.sanitizedCount, 6)
    }
    if (bucket.count > 1) {
        addSignal(signals, "PARAM_HOTSPOT", bucket.count, Math.min(14, 4 + (bucket.count * 2)))
    }
    if (bucket.hasFinding && bucket.hasRuntimeEvent) {
        addSignal(signals, "FINDING_CORROBORATION", true, 10)
    }
    return signals
}

function buildBucketManualSteps(bucket = {}) {
    switch (bucket.bucket) {
    case "client_execution":
        return [
            "Replay the same client-side source on the route and confirm the sink remains reachable after page state changes.",
            "Trace the source into the reported DOM or code-execution sink and validate whether a real script execution path exists.",
            "If the bucket is route-controlled, retest the same sink across SPA route transitions and refreshes."
        ]
    case "navigation_and_route_control":
        return [
            "Reproduce the route with controlled navigation inputs and observe whether client-side redirects or route transitions change.",
            "Check for dangerous URL schemes, forced-browse behavior, or privileged route rendering tied to the same source.",
            "Confirm whether the server independently enforces the same navigation or route decision."
        ]
    case "client_authz_and_state":
        return [
            "Toggle the same client state, flag, role hint, or route condition and verify whether privileged UI or actions become reachable.",
            "Compare the client-side state decision with direct server requests to confirm whether enforcement exists off the frontend.",
            "Promote to authz validation only after the state signal is reproducible and tied to a meaningful action."
        ]
    case "data_exposure_and_storage":
        return [
            "Inspect the same route and client state for token, secret, or hidden data persistence in storage, cookies, or runtime objects.",
            "Trace whether the exposed value influences follow-up requests, auth headers, or client-side decisions.",
            "Validate whether the same data is still reachable after reload, logout, or route changes."
        ]
    case "cross_context_messaging":
        return [
            "Replay the same messaging flow with controlled origins or payloads and verify whether receiver-side handling changes.",
            "Check whether cross-origin data can reach DOM, navigation, or execution sinks without strict origin validation.",
            "Compare sender-side assumptions with receiver-side enforcement before escalating."
        ]
    case "runtime_integrity_and_third_party":
        return [
            "Confirm whether the same third-party or runtime integrity path is stable across reload and clean-session states.",
            "Trace whether the signal leads to script loading, worker bootstrap, prototype mutation, or policy bypass behavior.",
            "Correlate the runtime signal with any vulnerable dependency or trusted-origin assumption before active validation."
        ]
    default:
        return [
            "Reproduce the route with the same client state and source value to confirm the runtime signal is stable.",
            "Trace the client-side source into the reported sink and verify whether server-side controls rely on the same assumption.",
            "Promote to targeted active validation only after confirming the client signal is reachable and meaningful."
        ]
    }
}

function mergeBucketEvidence(bucket = {}, input = {}) {
    const refs = normalizeRuntimeEventRefs(input, bucket.routeKey)
    refs.forEach((ref) => {
        if (bucket.evidenceRefs.length >= MAX_EVIDENCE_REFS) return
        bucket.evidenceRefs.push(ref)
    })
}

function buildDiscoveryBucket(bucket = {}) {
    const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
    const subtypes = Array.from(bucket.subtypes).sort((a, b) => a.localeCompare(b))
    const legacyFamilies = Array.from(bucket.legacyFamilies).sort((a, b) => a.localeCompare(b))
    const sourceKinds = Array.from(bucket.sourceKinds).sort((a, b) => a.localeCompare(b))
    const dataKinds = Array.from(bucket.dataKinds).sort((a, b) => a.localeCompare(b))
    const trustLevels = Array.from(bucket.trustLevels).sort((a, b) => a.localeCompare(b))
    const trustDecisions = Array.from(bucket.trustDecisions).sort((a, b) => a.localeCompare(b))
    const sanitizerIds = Array.from(bucket.sanitizerIds).sort((a, b) => a.localeCompare(b))
    const corroboratingEngines = Array.from(bucket.corroboratingEngines).sort((a, b) => a.localeCompare(b))
    return {
        id: `iastbucket:${bucket.routeKey}|${bucket.paramKey}|${bucket.bucket}`,
        bucket: bucket.bucket,
        subtype: subtypes[0] || "runtime_signal",
        subtypes,
        legacyFamilies,
        routeKey: bucket.routeKey,
        paramKey: bucket.paramKey,
        priority: bucket.priority,
        severity: bucket.severity,
        hits: bucket.count,
        sinkId: bucket.primarySink,
        sourceKinds,
        dataKinds,
        trustLevels,
        trustDecisions,
        crossOrigin: bucket.crossOrigin,
        routeControlled: bucket.routeControlled,
        sanitizedCount: bucket.sanitizedCount,
        sanitizerIds,
        thirdParty: bucket.thirdParty,
        authLike: bucket.authLike,
        corroboratingEngines,
        candidateType: bucketCandidateType(bucket),
        evidenceRefs
    }
}

export function runRuleIastRuntimeSignals(context = {}) {
    const scanResult = context?.scanResult && typeof context.scanResult === "object" ? context.scanResult : {}
    const hostHint = toNonEmptyString(scanResult?.host)
    const inputs = buildBucketInputList(scanResult, hostHint)
    if (!inputs.length) {
        return {
            ruleCode: RULE_CODE,
            emits: ["pattern", "candidates"],
            signals: [],
            patterns: [],
            candidateSeeds: [],
            discovery: {
                iastBuckets: []
            }
        }
    }

    const buckets = new Map()

    inputs.forEach((input) => {
        const key = `${input.routeKey}|${input.paramKey}|${input.bucket}`
        if (!buckets.has(key)) {
            buckets.set(key, {
                routeKey: input.routeKey,
                routeFamilyKey: input.routeFamilyKey,
                paramKey: input.paramKey,
                bucket: input.bucket,
                subtypes: new Set(),
                legacyFamilies: new Set(),
                sourceKinds: new Set(),
                dataKinds: new Set(),
                trustLevels: new Set(),
                trustDecisions: new Set(),
                sanitizerIds: new Set(),
                corroboratingEngines: new Set(["IAST"]),
                count: 0,
                crossOrigin: false,
                sanitizedCount: 0,
                routeControlled: false,
                thirdParty: false,
                authLike: false,
                primarySink: input.primarySink,
                primaryReason: input.primaryReason,
                severity: String(input.severity || "low").toLowerCase(),
                evidenceRefs: [],
                hasFinding: false,
                hasRuntimeEvent: false,
                _seenEntries: new Set()
            })
        }
        const bucket = buckets.get(key)
        bucket.subtypes.add(input.subtype || "runtime_signal")
        bucket.legacyFamilies.add(input.legacyFamily || "client_runtime")
        if (input.sourceKind) {
            bucket.sourceKinds.add(String(input.sourceKind).toLowerCase())
        }
        if (input.dataKind) {
            bucket.dataKinds.add(String(input.dataKind).toLowerCase())
        }
        if (input.trustLevel) {
            bucket.trustLevels.add(String(input.trustLevel).toLowerCase())
        }
        if (input.trustDecision) {
            bucket.trustDecisions.add(String(input.trustDecision).toLowerCase())
        }
        if (!bucket._seenEntries.has(input.uniqueKey)) {
            bucket.count += 1
            bucket._seenEntries.add(input.uniqueKey)
        }
        if (!bucket.primarySink && input.primarySink) {
            bucket.primarySink = input.primarySink
        }
        if (!bucket.primaryReason && input.primaryReason) {
            bucket.primaryReason = input.primaryReason
        }
        if (severityRank(input.severity) > severityRank(bucket.severity)) {
            bucket.severity = input.severity
        }
        if (input.crossOrigin) bucket.crossOrigin = true
        if (input.routeControlled) bucket.routeControlled = true
        if (input.thirdParty) bucket.thirdParty = true
        if (input.authLike) bucket.authLike = true
        if (input.hasFinding) bucket.hasFinding = true
        if (input.hasRuntimeEvent) bucket.hasRuntimeEvent = true
        bucket.sanitizedCount += Number(input.sanitizedCount || 0)
        if (Array.isArray(input.sanitizerIds)) {
            input.sanitizerIds.forEach((id) => {
                const normalized = toNonEmptyString(id)
                if (normalized) bucket.sanitizerIds.add(normalized)
            })
        }
        mergeBucketEvidence(bucket, input)
    })

    const ranked = Array.from(buckets.values())
        .map((bucket) => {
            const relatedEngines = context?.routeEnginesByFamily?.get(bucket.routeFamilyKey)
            if (relatedEngines && typeof relatedEngines.forEach === "function") {
                relatedEngines.forEach((engine) => {
                    const normalized = toNonEmptyString(engine)
                    if (normalized) bucket.corroboratingEngines.add(normalized)
                })
            }
            bucket.priority = bucketWeight(bucket.bucket)
                + Math.min(16, bucket.count * 2)
                + (bucket.crossOrigin ? 8 : 0)
                + (bucket.hasFinding ? 6 : 0)
                + (bucket.hasRuntimeEvent ? 4 : 0)
                + (bucket.thirdParty ? 6 : 0)
            return bucket
        })
        .sort((a, b) => {
            if (b.priority !== a.priority) return b.priority - a.priority
            return `${a.routeKey}|${a.paramKey}|${a.bucket}`.localeCompare(`${b.routeKey}|${b.paramKey}|${b.bucket}`)
        })
        .slice(0, MAX_BUCKETS)

    const patterns = []
    const candidateSeeds = []

    ranked.slice(0, MAX_CANDIDATES).forEach((bucket) => {
        const routeParts = splitRouteKey(bucket.routeKey)
        const evidenceRefs = normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        const signals = buildBucketSignals(bucket)
        const engineSignals = Array.from(bucket.corroboratingEngines).sort((a, b) => a.localeCompare(b))

        patterns.push({
            ruleCode: RULE_CODE,
            title: bucketPatternTitle(bucket, routeParts),
            type: "IAST_DISCOVERY_BUCKET",
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            priority: bucket.priority,
            signals: {
                source: "iast_bucket_aggregation",
                bucket: bucket.bucket,
                subtype: Array.from(bucket.subtypes).sort((a, b) => a.localeCompare(b))[0] || "runtime_signal",
                hits: bucket.count,
                sinkId: bucket.primarySink,
                detectionReason: bucket.primaryReason || null
            },
            evidenceRefs
        })

        candidateSeeds.push({
            createdByRule: RULE_CODE,
            type: bucketCandidateType(bucket),
            title: bucketCandidateTitle(bucket, routeParts),
            routeKey: bucket.routeKey,
            paramKey: bucket.paramKey,
            engineSignals,
            repeatabilityCount: bucket.count,
            signals,
            evidenceRefs,
            manualSteps: buildBucketManualSteps(bucket)
        })
    })

    const discoveryBuckets = ranked
        .slice(0, MAX_DISCOVERY_BUCKETS)
        .map((bucket) => buildDiscoveryBucket(bucket))

    return {
        ruleCode: RULE_CODE,
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds,
        discovery: {
            iastBuckets: discoveryBuckets
        }
    }
}

export default runRuleIastRuntimeSignals
