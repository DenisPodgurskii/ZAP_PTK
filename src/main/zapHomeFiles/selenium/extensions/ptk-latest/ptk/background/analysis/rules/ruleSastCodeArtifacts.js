import { buildRouteKey, normalizeParamKey, splitRouteKey } from "../canonicalize.js"
import { normalizeEvidenceRefs } from "../evidenceRefs.js"

const MAX_EVIDENCE_REFS = 10

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function addSignal(signals, code, value, weight = null) {
    const signal = { code, value }
    if (Number.isFinite(Number(weight))) {
        signal.weight = Number(weight)
    }
    signals.push(signal)
}

function artifactEvidenceRef(artifact = {}, param = null) {
    return {
        type: "artifact",
        id: artifact?.id || null,
        loc: {
            kind: artifact?.artifactType || null,
            module: artifact?.moduleId || null,
            rule: artifact?.ruleId || null,
            route: artifact?.routeKey || null,
            param: param || null
        }
    }
}

function normalizeRouteKey(artifact = {}, hostHint = null) {
    return artifact?.routeKey || buildRouteKey({
        url: artifact?.resolvedUrl || artifact?.url || artifact?.path || artifact?.pageUrl || "/",
        method: artifact?.method || "*",
        host: hostHint
    })
}

function mergeEvidenceRefs(target = [], artifact = {}, param = null) {
    const refs = normalizeEvidenceRefs([
        ...target,
        artifactEvidenceRef(artifact, param)
    ], { maxRefs: MAX_EVIDENCE_REFS })
    return refs
}

function dedupeSorted(values = []) {
    return Array.from(new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean)))
        .sort((a, b) => a.localeCompare(b))
}

function listLength(value) {
    return Array.isArray(value) ? value.length : 0
}

function listIncludes(value, expected) {
    return Array.isArray(value) ? value.includes(expected) : false
}

function routePriority(bucket = {}) {
    let priority = 16
    if (bucket.adminLike) priority += 18
    if (listLength(bucket.authHints)) priority += 12
    if (listLength(bucket.protocolHints)) priority += 8
    if (listLength(bucket.environmentHints)) priority += 6
    if (listLength(bucket.frameworks)) priority += 4
    return priority
}

function endpointPriority(bucket = {}) {
    let priority = 18
    if (bucket.method && bucket.method !== "GET") priority += 8
    if (bucket.adminLike) priority += 16
    if (listLength(bucket.authHints)) priority += 10
    if (listLength(bucket.protocolHints)) priority += 10
    if (listIncludes(bucket.discoveryTags, "upload")) priority += 10
    if (listIncludes(bucket.discoveryTags, "signed-url")) priority += 10
    if (listIncludes(bucket.discoveryTags, "object-storage")) priority += 12
    if (listIncludes(bucket.discoveryTags, "internal-host")) priority += 12
    if (listLength(bucket.environmentHints)) priority += 6
    priority += Math.min(12, listLength(bucket.paramNames) * 2)
    priority += Math.min(12, listLength(bucket.bodyKeys) * 3)
    return priority
}

function graphqlPriority(bucket = {}) {
    let priority = 20
    if (listIncludes(bucket.operationTypes, "mutation")) priority += 12
    if (listIncludes(bucket.operationTypes, "subscription")) priority += 8
    if (bucket.adminLike) priority += 16
    priority += Math.min(10, listLength(bucket.variableNames) * 2)
    priority += Math.min(10, listLength(bucket.rootFields) * 2)
    return priority
}

function surfacePriority(bucket = {}) {
    let priority = 14
    if (bucket.surfaceType === "feature-flag") priority += 6
    if (bucket.surfaceType === "debug-toggle") priority += 4
    if (bucket.surfaceType === "role-gate") priority += 10
    if (bucket.surfaceType === "auth-flow") priority += 8
    if (bucket.adminLike) priority += 12
    priority += Math.min(6, listLength(bucket.hintNames))
    return priority
}

function hiddenParamPriority(bucket = {}) {
    let priority = 18
    if (bucket.container === "query") priority += 4
    if (bucket.hintType === "auth") priority += 12
    if (bucket.hintType === "feature-flag") priority += 10
    if (bucket.hintType === "navigation") priority += 8
    if (bucket.hintType === "signature") priority += 12
    if (bucket.hintType === "upload") priority += 8
    if (bucket.adminLike) priority += 10
    return priority
}

function gadgetPriority(bucket = {}) {
    let priority = 16
    if (bucket.gadgetType === "message-listener" || bucket.gadgetType === "postmessage-emitter") priority += 8
    if (bucket.gadgetType === "dom-html-sink") priority += 10
    if (bucket.gadgetType === "prototype-mutation") priority += 12
    if (bucket.gadgetType === "code-exec-sink") priority += 14
    return priority
}

function buildRouteManualSteps(routeParts = {}) {
    return [
        `Browse directly to ${routeParts.pathTemplate || "/"} and confirm whether the route is reachable unauthenticated.`,
        "Inspect client-side guards, role checks, and route loaders to see whether they only enforce access in the browser.",
        "Map every API call triggered by this route and replay them outside the intended UI flow."
    ]
}

function buildEndpointManualSteps(endpoint = {}, routeParts = {}) {
    const steps = [
        `Replay ${endpoint.method || "GET"} ${routeParts.pathTemplate || "/"} with and without the intended auth/session context.`,
        "Mutate discovered query/body/header keys individually to confirm hidden parameters, state transitions, and authz gaps.",
        "Check whether this endpoint is reachable from undocumented routes, feature flags, or admin-only flows."
    ]
    if ((endpoint.discoveryTags || []).includes("upload")) {
        steps.push("Exercise file, content-type, filename, and signed-upload variations to look for unrestricted upload or parser gaps.")
    }
    if ((endpoint.discoveryTags || []).includes("signed-url") || (endpoint.discoveryTags || []).includes("object-storage")) {
        steps.push("Replay the signed or storage-backed request out of flow and test key, bucket, expiry, and content-type manipulation.")
    }
    if ((endpoint.discoveryTags || []).includes("internal-host")) {
        steps.push("Check whether the discovered internal or non-production host is reachable directly and whether it exposes weaker authz or debug behavior.")
    }
    return steps
}

function buildGraphqlManualSteps(bucket = {}, routeParts = {}) {
    return [
        `Replay GraphQL ${bucket.operationTypes[0] || "query"} traffic against ${routeParts.pathTemplate || "/graphql"} outside the intended UI flow.`,
        "Mutate variables, operation names, and root fields to look for undocumented mutations, overbroad field access, and IDOR-style authz gaps.",
        "If schema introspection is disabled, enumerate the discovered operation and field names directly from the client bundle."
    ]
}

function buildSurfaceManualSteps(bucket = {}) {
    const steps = [
        `Trace the ${bucket.surfaceType || "gated"} code path from the browser and identify which runtime checks or feature flags gate it.`,
        "Toggle the discovered flag/role signal in local state, storage, query params, or client config and compare the resulting requests.",
        "Replay any gated requests directly to confirm whether enforcement exists server-side."
    ]
    if (bucket.surfaceType === "auth-flow") {
        steps.push("Map registration, challenge, assertion, and recovery endpoints around the discovered auth flow and compare fallback behavior.")
    }
    return steps
}

function buildHiddenParamManualSteps(bucket = {}) {
    const steps = [
        `Replay the related request or route with ${bucket.paramName} added explicitly in the ${bucket.container || "query"} container.`,
        "Enumerate alternative values and compare response differences, state changes, and access-control decisions.",
        "Cross-check whether the parameter only gates UI behaviour or whether the backend trusts it directly."
    ]
    if (bucket.hintType === "signature") {
        steps.push("Verify whether signature or expiry parameters are actually enforced server-side and whether they can be replayed or transplanted.")
    }
    return steps
}

function buildGadgetManualSteps(bucket = {}) {
    if (bucket.gadgetType === "message-listener" || bucket.gadgetType === "postmessage-emitter") {
        return [
            "Craft cross-origin postMessage payloads that reach the discovered listener/emitter boundary.",
            "Trace whether message data influences DOM, navigation, auth state, or request construction.",
            "Confirm whether origin validation is strict and whether structured payload validation actually happens before the sensitive sink."
        ]
    }
    if (bucket.gadgetType === "prototype-mutation") {
        return [
            "Trace whether attacker-controlled objects can reach the discovered prototype mutation primitive.",
            "Try polluted keys such as __proto__, constructor.prototype, and nested merge paths to confirm impact.",
            "Check whether polluted properties later influence routing, templating, or auth decisions."
        ]
    }
    return [
        "Trace whether attacker-controlled data can reach the discovered sink primitive through message, URL, storage, or form inputs.",
        "Exercise the sink with benign structured payloads first to understand required shape and encoding.",
        "Confirm whether context-aware sanitization is consistently applied before the sink."
    ]
}

export function runRuleSastCodeArtifacts(context = {}) {
    const scanResult = context?.scanResult && typeof context.scanResult === "object" ? context.scanResult : {}
    const hostHint = toNonEmptyString(scanResult?.host)
    const sastArtifacts = scanResult?.codeArtifacts?.sast && typeof scanResult.codeArtifacts.sast === "object"
        ? scanResult.codeArtifacts.sast
        : {}
    const routes = Array.isArray(sastArtifacts.routes) ? sastArtifacts.routes : []
    const endpoints = Array.isArray(sastArtifacts.endpoints) ? sastArtifacts.endpoints : []
    const graphql = Array.isArray(sastArtifacts.graphql) ? sastArtifacts.graphql : []
    const surfaces = Array.isArray(sastArtifacts.surfaces) ? sastArtifacts.surfaces : []
    const hiddenParams = Array.isArray(sastArtifacts.hiddenParams) ? sastArtifacts.hiddenParams : []
    const gadgets = Array.isArray(sastArtifacts.gadgets) ? sastArtifacts.gadgets : []

    if (!routes.length && !endpoints.length && !graphql.length && !surfaces.length && !hiddenParams.length && !gadgets.length) {
        return {
            ruleCode: "R11_SAST_CODE_ARTIFACTS",
            emits: ["pattern", "candidates"],
            signals: [],
            patterns: [],
            candidateSeeds: []
        }
    }

    const routeBuckets = new Map()
    routes.forEach((artifact) => {
        if (!artifact || typeof artifact !== "object") return
        const routeKey = normalizeRouteKey(artifact, hostHint)
        if (!routeBuckets.has(routeKey)) {
            routeBuckets.set(routeKey, {
                routeKey,
                paths: [],
                frameworks: [],
                authHints: [],
                protocolHints: [],
                environmentHints: [],
                adminLike: false,
                evidenceRefs: []
            })
        }
        const bucket = routeBuckets.get(routeKey)
        bucket.paths.push(artifact.path || String(routeKey).split("|")[2] || "/")
        bucket.frameworks.push(artifact.framework || "route-config")
        bucket.authHints.push(...(Array.isArray(artifact.authHints) ? artifact.authHints : []))
        bucket.protocolHints.push(...(Array.isArray(artifact.protocolHints) ? artifact.protocolHints : []))
        bucket.environmentHints.push(...(Array.isArray(artifact.environmentHints) ? artifact.environmentHints : []))
        if (artifact.adminLike) bucket.adminLike = true
        bucket.evidenceRefs = mergeEvidenceRefs(bucket.evidenceRefs, artifact)
    })

    const endpointBuckets = new Map()
    endpoints.forEach((artifact) => {
        if (!artifact || typeof artifact !== "object") return
        const routeKey = normalizeRouteKey(artifact, hostHint)
        const method = String(artifact.method || "GET").toUpperCase()
        const transport = String(artifact.transport || "request").toLowerCase()
        const bucketKey = `${transport}|${method}|${routeKey}`
        if (!endpointBuckets.has(bucketKey)) {
            endpointBuckets.set(bucketKey, {
                transport,
                method,
                routeKey,
                urlSamples: [],
                authHints: [],
                protocolHints: [],
                discoveryTags: [],
                environmentHints: [],
                storageHints: [],
                adminLike: false,
                paramNames: [],
                bodyKeys: [],
                headerNames: [],
                evidenceRefs: []
            })
        }
        const bucket = endpointBuckets.get(bucketKey)
        bucket.urlSamples.push(artifact.resolvedUrl || artifact.url || String(routeKey).split("|")[2] || "/")
        bucket.authHints.push(...(Array.isArray(artifact.authHints) ? artifact.authHints : []))
        bucket.protocolHints.push(...(Array.isArray(artifact.protocolHints) ? artifact.protocolHints : []))
        bucket.discoveryTags.push(...(Array.isArray(artifact.discoveryTags) ? artifact.discoveryTags : []))
        bucket.environmentHints.push(...(Array.isArray(artifact.environmentHints) ? artifact.environmentHints : []))
        bucket.storageHints.push(...(Array.isArray(artifact.storageHints) ? artifact.storageHints : []))
        bucket.paramNames.push(...(Array.isArray(artifact.paramNames) ? artifact.paramNames : []))
        bucket.bodyKeys.push(...(Array.isArray(artifact.bodyKeys) ? artifact.bodyKeys : []))
        bucket.headerNames.push(...(Array.isArray(artifact.headerNames) ? artifact.headerNames : []))
        if (artifact.adminLike) bucket.adminLike = true
        const representativeParam = (artifact.paramNames || [])[0] || (artifact.bodyKeys || [])[0] || (artifact.headerNames || [])[0] || null
        bucket.evidenceRefs = mergeEvidenceRefs(bucket.evidenceRefs, artifact, representativeParam)
    })

    const graphqlBuckets = new Map()
    graphql.forEach((artifact) => {
        if (!artifact || typeof artifact !== "object") return
        const routeKey = normalizeRouteKey(artifact, hostHint)
        const opKey = dedupeSorted(artifact.operationNames || []).join(",") || "anonymous"
        const bucketKey = `${routeKey}|${opKey}`
        if (!graphqlBuckets.has(bucketKey)) {
            graphqlBuckets.set(bucketKey, {
                routeKey,
                method: String(artifact.method || "POST").toUpperCase(),
                transports: [],
                urlSamples: [],
                operationTypes: [],
                operationNames: [],
                rootFields: [],
                variableNames: [],
                authHints: [],
                adminLike: false,
                evidenceRefs: []
            })
        }
        const bucket = graphqlBuckets.get(bucketKey)
        bucket.transports.push(artifact.transport || artifact.clientKind || "graphql")
        bucket.urlSamples.push(artifact.resolvedUrl || artifact.url || "/graphql")
        bucket.operationTypes.push(...(Array.isArray(artifact.operationTypes) ? artifact.operationTypes : []))
        bucket.operationNames.push(...(Array.isArray(artifact.operationNames) ? artifact.operationNames : []))
        bucket.rootFields.push(...(Array.isArray(artifact.rootFields) ? artifact.rootFields : []))
        bucket.variableNames.push(...(Array.isArray(artifact.variableNames) ? artifact.variableNames : []))
        bucket.authHints.push(...(Array.isArray(artifact.authHints) ? artifact.authHints : []))
        if (artifact.adminLike) bucket.adminLike = true
        const representativeParam = (artifact.variableNames || [])[0] || null
        bucket.evidenceRefs = mergeEvidenceRefs(bucket.evidenceRefs, artifact, representativeParam)
    })

    const surfaceBuckets = new Map()
    surfaces.forEach((artifact) => {
        if (!artifact || typeof artifact !== "object") return
        const routeKey = normalizeRouteKey(artifact, hostHint)
        const surfaceType = String(artifact.surfaceType || "surface")
        const label = String(artifact.label || surfaceType)
        const bucketKey = `${surfaceType}|${routeKey}|${label}`
        if (!surfaceBuckets.has(bucketKey)) {
            surfaceBuckets.set(bucketKey, {
                routeKey,
                surfaceType,
                label,
                hintNames: [],
                adminLike: false,
                evidenceRefs: []
            })
        }
        const bucket = surfaceBuckets.get(bucketKey)
        bucket.hintNames.push(...(Array.isArray(artifact.hintNames) ? artifact.hintNames : []))
        if (artifact.adminLike) bucket.adminLike = true
        bucket.evidenceRefs = mergeEvidenceRefs(bucket.evidenceRefs, artifact)
    })

    const hiddenParamBuckets = new Map()
    hiddenParams.forEach((artifact) => {
        if (!artifact || typeof artifact !== "object") return
        const routeKey = normalizeRouteKey(artifact, hostHint)
        const paramName = String(artifact.paramName || "")
        const container = String(artifact.container || "param")
        const bucketKey = `${container}|${routeKey}|${paramName}`
        if (!hiddenParamBuckets.has(bucketKey)) {
            hiddenParamBuckets.set(bucketKey, {
                routeKey,
                paramName,
                container,
                actions: [],
                hintType: artifact.hintType || "generic",
                adminLike: false,
                evidenceRefs: []
            })
        }
        const bucket = hiddenParamBuckets.get(bucketKey)
        bucket.actions.push(artifact.action || "read")
        if (artifact.hintType && bucket.hintType === "generic") {
            bucket.hintType = artifact.hintType
        }
        if (artifact.adminLike) bucket.adminLike = true
        bucket.evidenceRefs = mergeEvidenceRefs(bucket.evidenceRefs, artifact, paramName)
    })

    const gadgetBuckets = new Map()
    gadgets.forEach((artifact) => {
        if (!artifact || typeof artifact !== "object") return
        const routeKey = normalizeRouteKey(artifact, hostHint)
        const gadgetType = String(artifact.gadgetType || "gadget")
        const label = String(artifact.label || gadgetType)
        const bucketKey = `${gadgetType}|${routeKey}|${label}`
        if (!gadgetBuckets.has(bucketKey)) {
            gadgetBuckets.set(bucketKey, {
                routeKey,
                gadgetType,
                label,
                evidenceRefs: []
            })
        }
        const bucket = gadgetBuckets.get(bucketKey)
        bucket.evidenceRefs = mergeEvidenceRefs(bucket.evidenceRefs, artifact)
    })

    const patterns = []
    const candidateSeeds = []

    Array.from(routeBuckets.values()).forEach((bucket) => {
        bucket.paths = dedupeSorted(bucket.paths)
        bucket.frameworks = dedupeSorted(bucket.frameworks)
        bucket.authHints = dedupeSorted(bucket.authHints)
        bucket.protocolHints = dedupeSorted(bucket.protocolHints)
        bucket.environmentHints = dedupeSorted(bucket.environmentHints)
        const routeParts = splitRouteKey(bucket.routeKey)
        const priority = routePriority(bucket)

        patterns.push({
            ruleCode: "R11_SAST_CODE_ARTIFACTS",
            title: `Code-discovered route ${routeParts.pathTemplate}`,
            type: "SAST_ROUTE_ARTIFACT",
            routeKey: bucket.routeKey,
            paramKey: "param:<none>",
            priority,
            signals: {
                source: "sast_code_artifacts",
                artifactType: "route",
                frameworks: bucket.frameworks,
                authHints: bucket.authHints,
                protocolHints: bucket.protocolHints,
                environmentHints: bucket.environmentHints,
                adminLike: bucket.adminLike
            },
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        })

        const signals = []
        addSignal(signals, "CODE_ROUTE_DISCOVERY", bucket.paths[0] || routeParts.pathTemplate, 14)
        if (bucket.frameworks.length) {
            addSignal(signals, "FRAMEWORK_ROUTE_HINT", bucket.frameworks.join(","), 4)
        }
        if (bucket.authHints.length || bucket.adminLike) {
            addSignal(signals, "AUTH_SESSION_SIGNAL", bucket.authHints[0] || "route_guard", bucket.adminLike ? 14 : 10)
        }
        if (bucket.protocolHints.length) {
            addSignal(signals, "AUTH_FLOW_DISCOVERY", bucket.protocolHints.join(","), 10)
        }
        if (bucket.environmentHints.length) {
            addSignal(signals, "NONPROD_ROUTE_HINT", bucket.environmentHints.join(","), 8)
        }

        candidateSeeds.push({
            createdByRule: "R11_SAST_CODE_ARTIFACTS",
            type: "CODE_HOTSPOT",
            title: `Validate code-discovered route ${routeParts.pathTemplate}`,
            routeKey: bucket.routeKey,
            paramKey: "param:<none>",
            engineSignals: ["SAST"],
            repeatabilityCount: 1,
            signals,
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS }),
            manualSteps: buildRouteManualSteps(routeParts)
        })
    })

    Array.from(endpointBuckets.values()).forEach((bucket) => {
        bucket.urlSamples = dedupeSorted(bucket.urlSamples)
        bucket.authHints = dedupeSorted(bucket.authHints)
        bucket.protocolHints = dedupeSorted(bucket.protocolHints)
        bucket.discoveryTags = dedupeSorted(bucket.discoveryTags)
        bucket.environmentHints = dedupeSorted(bucket.environmentHints)
        bucket.storageHints = dedupeSorted(bucket.storageHints)
        bucket.paramNames = dedupeSorted(bucket.paramNames)
        bucket.bodyKeys = dedupeSorted(bucket.bodyKeys)
        bucket.headerNames = dedupeSorted(bucket.headerNames)
        const routeParts = splitRouteKey(bucket.routeKey)
        const representativeParam = bucket.paramNames[0] || bucket.bodyKeys[0] || bucket.headerNames[0] || "<none>"
        const paramLocation = bucket.paramNames.length ? "query" : (bucket.bodyKeys.length ? "json" : (bucket.headerNames.length ? "header" : "param"))
        const priority = endpointPriority(bucket)

        patterns.push({
            ruleCode: "R11_SAST_CODE_ARTIFACTS",
            title: `Code-discovered endpoint ${bucket.method} ${routeParts.pathTemplate}`,
            type: "SAST_ENDPOINT_ARTIFACT",
            routeKey: bucket.routeKey,
            paramKey: normalizeParamKey(representativeParam, paramLocation),
            priority,
            signals: {
                source: "sast_code_artifacts",
                artifactType: "endpoint",
                transport: bucket.transport,
                method: bucket.method,
                discoveryTags: bucket.discoveryTags,
                protocolHints: bucket.protocolHints,
                environmentHints: bucket.environmentHints,
                storageHints: bucket.storageHints,
                params: bucket.paramNames,
                bodyKeys: bucket.bodyKeys,
                headerNames: bucket.headerNames,
                adminLike: bucket.adminLike
            },
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        })

        const signals = []
        addSignal(signals, "CODE_ENDPOINT_DISCOVERY", `${bucket.method} ${routeParts.pathTemplate}`, 16)
        if (bucket.method !== "GET") {
            addSignal(signals, "STATE_CHANGING_ENDPOINT", bucket.method, 8)
        }
        if (bucket.paramNames.length) {
            addSignal(signals, "PARAM_HOTSPOT", bucket.paramNames.length, Math.min(12, 4 + (bucket.paramNames.length * 2)))
        }
        if (bucket.bodyKeys.length) {
            addSignal(signals, "BODY_KEY_DISCOVERY", bucket.bodyKeys.join(","), Math.min(14, 6 + (bucket.bodyKeys.length * 2)))
        }
        if (bucket.headerNames.length) {
            addSignal(signals, "HEADER_KEY_DISCOVERY", bucket.headerNames.join(","), Math.min(10, 4 + bucket.headerNames.length))
        }
        if (bucket.authHints.length || bucket.adminLike) {
            addSignal(signals, "AUTH_SESSION_SIGNAL", bucket.authHints[0] || "auth_header", bucket.adminLike ? 14 : 10)
        }
        if (bucket.protocolHints.length) {
            addSignal(signals, "AUTH_FLOW_DISCOVERY", bucket.protocolHints.join(","), 12)
        }
        if (bucket.discoveryTags.includes("upload")) {
            addSignal(signals, "UPLOAD_SURFACE_DISCOVERY", bucket.urlSamples[0] || routeParts.pathTemplate, 12)
        }
        if (bucket.discoveryTags.includes("signed-url")) {
            addSignal(signals, "SIGNED_URL_DISCOVERY", bucket.urlSamples[0] || routeParts.pathTemplate, 14)
        }
        if (bucket.discoveryTags.includes("object-storage")) {
            addSignal(signals, "OBJECT_STORAGE_DISCOVERY", bucket.storageHints[0] || bucket.urlSamples[0] || routeParts.pathTemplate, 14)
        }
        if (bucket.discoveryTags.includes("internal-host") || bucket.environmentHints.length) {
            addSignal(signals, "NONPROD_ENDPOINT_HINT", bucket.environmentHints[0] || bucket.urlSamples[0] || routeParts.pathTemplate, 12)
        }

        candidateSeeds.push({
            createdByRule: "R11_SAST_CODE_ARTIFACTS",
            type: "CODE_HOTSPOT",
            title: `Validate code-discovered endpoint ${bucket.method} ${routeParts.pathTemplate}`,
            routeKey: bucket.routeKey,
            paramKey: normalizeParamKey(representativeParam, paramLocation),
            engineSignals: ["SAST"],
            repeatabilityCount: 1,
            signals,
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS }),
            manualSteps: buildEndpointManualSteps(bucket, routeParts)
        })
    })

    Array.from(graphqlBuckets.values()).forEach((bucket) => {
        bucket.transports = dedupeSorted(bucket.transports)
        bucket.urlSamples = dedupeSorted(bucket.urlSamples)
        bucket.operationTypes = dedupeSorted(bucket.operationTypes)
        bucket.operationNames = dedupeSorted(bucket.operationNames)
        bucket.rootFields = dedupeSorted(bucket.rootFields)
        bucket.variableNames = dedupeSorted(bucket.variableNames)
        bucket.authHints = dedupeSorted(bucket.authHints)
        const routeParts = splitRouteKey(bucket.routeKey)
        const representativeVar = bucket.variableNames[0] || "<none>"
        const priority = graphqlPriority(bucket)

        patterns.push({
            ruleCode: "R11_SAST_CODE_ARTIFACTS",
            title: `Code-discovered GraphQL ${bucket.operationNames[0] || bucket.operationTypes[0] || "operation"}`,
            type: "SAST_GRAPHQL_ARTIFACT",
            routeKey: bucket.routeKey,
            paramKey: normalizeParamKey(representativeVar, "json"),
            priority,
            signals: {
                source: "sast_code_artifacts",
                artifactType: "graphql",
                transports: bucket.transports,
                operationTypes: bucket.operationTypes,
                operationNames: bucket.operationNames,
                rootFields: bucket.rootFields,
                variableNames: bucket.variableNames,
                adminLike: bucket.adminLike
            },
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        })

        const signals = []
        addSignal(signals, "GRAPHQL_OPERATION_DISCOVERY", bucket.operationNames[0] || bucket.rootFields[0] || "anonymous", 16)
        if (bucket.operationTypes.includes("mutation")) {
            addSignal(signals, "GRAPHQL_MUTATION", bucket.operationNames[0] || "mutation", 12)
        }
        if (bucket.operationTypes.includes("subscription")) {
            addSignal(signals, "GRAPHQL_SUBSCRIPTION", bucket.operationNames[0] || "subscription", 8)
        }
        if (bucket.variableNames.length) {
            addSignal(signals, "GRAPHQL_VARIABLE_DISCOVERY", bucket.variableNames.join(","), Math.min(12, 4 + (bucket.variableNames.length * 2)))
        }
        if (bucket.rootFields.length) {
            addSignal(signals, "GRAPHQL_FIELD_DISCOVERY", bucket.rootFields.join(","), Math.min(12, 4 + (bucket.rootFields.length * 2)))
        }
        if (bucket.authHints.length || bucket.adminLike) {
            addSignal(signals, "AUTH_SESSION_SIGNAL", bucket.authHints[0] || "graphql_auth", bucket.adminLike ? 14 : 10)
        }

        candidateSeeds.push({
            createdByRule: "R11_SAST_CODE_ARTIFACTS",
            type: "CODE_HOTSPOT",
            title: `Probe GraphQL operation ${bucket.operationNames[0] || routeParts.pathTemplate}`,
            routeKey: bucket.routeKey,
            paramKey: normalizeParamKey(representativeVar, "json"),
            engineSignals: ["SAST"],
            repeatabilityCount: 1,
            signals,
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS }),
            manualSteps: buildGraphqlManualSteps(bucket, routeParts)
        })
    })

    Array.from(surfaceBuckets.values()).forEach((bucket) => {
        bucket.hintNames = dedupeSorted(bucket.hintNames)
        const priority = surfacePriority(bucket)

        patterns.push({
            ruleCode: "R11_SAST_CODE_ARTIFACTS",
            title: `Code-discovered ${bucket.surfaceType} ${bucket.label}`,
            type: "SAST_SURFACE_ARTIFACT",
            routeKey: bucket.routeKey,
            paramKey: "param:<none>",
            priority,
            signals: {
                source: "sast_code_artifacts",
                artifactType: "surface",
                surfaceType: bucket.surfaceType,
                hintNames: bucket.hintNames,
                adminLike: bucket.adminLike
            },
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        })

        const signals = []
        if (bucket.surfaceType === "feature-flag") {
            addSignal(signals, "FEATURE_FLAG_DISCOVERY", bucket.label, 14)
        } else if (bucket.surfaceType === "debug-toggle") {
            addSignal(signals, "DEBUG_SURFACE_DISCOVERY", bucket.label, 12)
        } else if (bucket.surfaceType === "auth-flow") {
            addSignal(signals, "AUTH_FLOW_DISCOVERY", bucket.label, 14)
        } else {
            addSignal(signals, "ADMIN_SURFACE_DISCOVERY", bucket.label, bucket.adminLike ? 16 : 12)
        }
        if (bucket.adminLike) {
            addSignal(signals, "AUTH_SESSION_SIGNAL", bucket.label, 12)
        }

        candidateSeeds.push({
            createdByRule: "R11_SAST_CODE_ARTIFACTS",
            type: "CODE_HOTSPOT",
            title: `Validate gated surface ${bucket.label}`,
            routeKey: bucket.routeKey,
            paramKey: "param:<none>",
            engineSignals: ["SAST"],
            repeatabilityCount: 1,
            signals,
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS }),
            manualSteps: buildSurfaceManualSteps(bucket)
        })
    })

    Array.from(hiddenParamBuckets.values()).forEach((bucket) => {
        bucket.actions = dedupeSorted(bucket.actions)
        const priority = hiddenParamPriority(bucket)
        const paramKey = normalizeParamKey(bucket.paramName || "<none>", bucket.container || "param")

        patterns.push({
            ruleCode: "R11_SAST_CODE_ARTIFACTS",
            title: `Code-discovered hidden parameter ${bucket.paramName}`,
            type: "SAST_HIDDEN_PARAM_ARTIFACT",
            routeKey: bucket.routeKey,
            paramKey,
            priority,
            signals: {
                source: "sast_code_artifacts",
                artifactType: "hidden_param",
                container: bucket.container,
                hintType: bucket.hintType,
                actions: bucket.actions,
                adminLike: bucket.adminLike
            },
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        })

        const signals = []
        addSignal(signals, "HIDDEN_PARAM_DISCOVERY", `${bucket.container}:${bucket.paramName}`, 16)
        if (bucket.hintType === "feature-flag") {
            addSignal(signals, "FEATURE_FLAG_DISCOVERY", bucket.paramName, 10)
        } else if (bucket.hintType === "navigation") {
            addSignal(signals, "NAVIGATION_CONTROL_PARAM", bucket.paramName, 10)
        } else if (bucket.hintType === "signature") {
            addSignal(signals, "SIGNED_URL_DISCOVERY", bucket.paramName, 14)
        } else if (bucket.hintType === "upload") {
            addSignal(signals, "UPLOAD_SURFACE_DISCOVERY", bucket.paramName, 10)
        } else if (bucket.hintType === "auth" || bucket.adminLike) {
            addSignal(signals, "AUTH_SESSION_SIGNAL", bucket.paramName, 12)
        } else if (bucket.hintType === "debug") {
            addSignal(signals, "DEBUG_SURFACE_DISCOVERY", bucket.paramName, 8)
        }

        candidateSeeds.push({
            createdByRule: "R11_SAST_CODE_ARTIFACTS",
            type: "CODE_HOTSPOT",
            title: `Probe hidden parameter ${bucket.paramName}`,
            routeKey: bucket.routeKey,
            paramKey,
            engineSignals: ["SAST"],
            repeatabilityCount: 1,
            signals,
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS }),
            manualSteps: buildHiddenParamManualSteps(bucket)
        })
    })

    Array.from(gadgetBuckets.values()).forEach((bucket) => {
        const priority = gadgetPriority(bucket)

        patterns.push({
            ruleCode: "R11_SAST_CODE_ARTIFACTS",
            title: `Code-discovered gadget ${bucket.label}`,
            type: "SAST_GADGET_ARTIFACT",
            routeKey: bucket.routeKey,
            paramKey: "param:<none>",
            priority,
            signals: {
                source: "sast_code_artifacts",
                artifactType: "gadget",
                gadgetType: bucket.gadgetType,
                label: bucket.label
            },
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS })
        })

        const signals = []
        if (bucket.gadgetType === "message-listener" || bucket.gadgetType === "postmessage-emitter") {
            addSignal(signals, "MESSAGE_TRUST_BOUNDARY", bucket.label, 12)
        } else if (bucket.gadgetType === "dom-html-sink") {
            addSignal(signals, "DOM_HTML_GADGET", bucket.label, 14)
        } else if (bucket.gadgetType === "prototype-mutation") {
            addSignal(signals, "PROTOTYPE_MUTATION_GADGET", bucket.label, 16)
        } else if (bucket.gadgetType === "code-exec-sink") {
            addSignal(signals, "CODE_EXECUTION_GADGET", bucket.label, 18)
        } else {
            addSignal(signals, "CODE_GADGET_DISCOVERY", bucket.label, 10)
        }

        candidateSeeds.push({
            createdByRule: "R11_SAST_CODE_ARTIFACTS",
            type: "CODE_HOTSPOT",
            title: `Trace gadget ${bucket.label}`,
            routeKey: bucket.routeKey,
            paramKey: "param:<none>",
            engineSignals: ["SAST"],
            repeatabilityCount: 1,
            signals,
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs, { maxRefs: MAX_EVIDENCE_REFS }),
            manualSteps: buildGadgetManualSteps(bucket)
        })
    })

    return {
        ruleCode: "R11_SAST_CODE_ARTIFACTS",
        emits: ["pattern", "candidates"],
        signals: [],
        patterns,
        candidateSeeds
    }
}

export default runRuleSastCodeArtifacts
