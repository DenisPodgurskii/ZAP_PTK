import CryptoES from "../../packages/crypto-es/index.js"
import {
    buildRouteFamilyKey,
    buildRouteKey,
    normalizeEngineName,
    normalizeMethod,
    normalizeParamKey
} from "./canonicalize.js"
import { normalizeEvidenceRefs } from "./evidenceRefs.js"
import { scoreCandidateSeeds } from "./scoring.js"
import runRule5xxCluster from "./rules/rule5xxCluster.js"
import runRuleErrorFingerprint from "./rules/ruleErrorFingerprint.js"
import runRuleParamHotspot from "./rules/ruleParamHotspot.js"
import runRuleCriticalGaps from "./rules/ruleCriticalGaps.js"
import runRuleAuthSessionDrift from "./rules/ruleAuthSessionDrift.js"
import runRuleLatencyOutliers from "./rules/ruleLatencyOutliers.js"
import runRuleInconsistentResourceBehavior from "./rules/ruleInconsistentResourceBehavior.js"
import runRulePassiveFindingSeeds from "./rules/rulePassiveFindingSeeds.js"
import runRuleTemplateRenderWorkflows from "./rules/ruleTemplateRenderWorkflows.js"
import runRuleIastRuntimeSignals from "./rules/ruleIastRuntimeSignals.js"
import runRuleSastCodeArtifacts from "./rules/ruleSastCodeArtifacts.js"

export const ANALYSIS_VERSION = "1.5.0"

const CACHE_KEY_PROP = "__ptkAnalysisCacheKey"
const ENGINE_ORDER = Object.freeze(["DAST", "IAST", "SAST", "SCA"])
const DEFAULT_CAPS = Object.freeze({
    maxAttackObservations: 50000,
    maxPassiveObservations: 50000,
    maxRuntimeEventsInspected: 100000,
    maxPatterns: 50,
    maxCandidates: 100
})

const RULES = Object.freeze([
    runRule5xxCluster,
    runRuleErrorFingerprint,
    runRuleParamHotspot,
    runRuleCriticalGaps,
    runRuleAuthSessionDrift,
    runRuleLatencyOutliers,
    runRuleInconsistentResourceBehavior,
    runRulePassiveFindingSeeds,
    runRuleTemplateRenderWorkflows,
    runRuleIastRuntimeSignals,
    runRuleSastCodeArtifacts
])

function clamp(num, min, max) {
    return Math.min(max, Math.max(min, num))
}

function hashHex(value) {
    return CryptoES.SHA256(String(value || "")).toString(CryptoES.enc.Hex)
}

function toNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const trimmed = String(value).trim()
    return trimmed.length ? trimmed : null
}

function getCacheKey(scanResult) {
    return scanResult && typeof scanResult === "object" ? scanResult[CACHE_KEY_PROP] : null
}

function setCacheKey(scanResult, key) {
    if (!scanResult || typeof scanResult !== "object") return
    try {
        Object.defineProperty(scanResult, CACHE_KEY_PROP, {
            value: key,
            writable: true,
            configurable: true,
            enumerable: false
        })
    } catch (_) {
        scanResult[CACHE_KEY_PROP] = key
    }
}

function buildPreviousAnalysisSignature(previousAnalysis = null) {
    if (!previousAnalysis || typeof previousAnalysis !== "object") return "none"
    const candidates = Array.isArray(previousAnalysis?.candidates) ? previousAnalysis.candidates : []
    if (!candidates.length) {
        return [
            previousAnalysis?.version || "",
            previousAnalysis?.scanId || "",
            "0"
        ].join("|")
    }
    const digest = candidates
        .map((candidate) => {
            const key = candidate?.suppressKey || candidate?.id || ""
            const score = Number(candidate?.score || 0)
            const confidence = String(candidate?.confidence || "low")
            return `${key}:${score}:${confidence}`
        })
        .sort((a, b) => a.localeCompare(b))
        .join("|")
    return [
        previousAnalysis?.version || "",
        previousAnalysis?.scanId || "",
        candidates.length,
        hashHex(digest).slice(0, 20)
    ].join("|")
}

function buildRelatedScansSignature(relatedScans = []) {
    if (!Array.isArray(relatedScans) || !relatedScans.length) return "none"
    const digest = relatedScans
        .map((scan) => {
            if (!scan || typeof scan !== "object") return ""
            return [
                scan?.scanId || "",
                normalizeEngineName(scan?.engine) || "",
                scan?.host || "",
                scan?.tabId ?? "",
                scan?.finishedAt || scan?.finished || scan?.startedAt || "",
                Array.isArray(scan?.findings) ? scan.findings.length : 0,
                Array.isArray(scan?.requests) ? scan.requests.length : 0,
                Array.isArray(scan?.runtimeEvents) ? scan.runtimeEvents.length : 0
            ].join("|")
        })
        .filter(Boolean)
        .sort((a, b) => a.localeCompare(b))
        .join("||")
    return `${relatedScans.length}:${hashHex(digest).slice(0, 20)}`
}

function buildCacheKey(scanResult, extraEnginesPresent = [], previousAnalysis = null, relatedScans = []) {
    if (!scanResult || typeof scanResult !== "object") return "empty"
    const findings = Array.isArray(scanResult.findings) ? scanResult.findings : []
    const requests = Array.isArray(scanResult.requests) ? scanResult.requests : []
    const runtimeEvents = Array.isArray(scanResult.runtimeEvents) ? scanResult.runtimeEvents : []
    const files = Array.isArray(scanResult.files) ? scanResult.files : []
    const sastArtifacts = scanResult?.codeArtifacts?.sast && typeof scanResult.codeArtifacts.sast === "object"
        ? scanResult.codeArtifacts.sast
        : {}
    const routes = Array.isArray(sastArtifacts.routes) ? sastArtifacts.routes : []
    const endpoints = Array.isArray(sastArtifacts.endpoints) ? sastArtifacts.endpoints : []
    const graphql = Array.isArray(sastArtifacts.graphql) ? sastArtifacts.graphql : []
    const surfaces = Array.isArray(sastArtifacts.surfaces) ? sastArtifacts.surfaces : []
    const hiddenParams = Array.isArray(sastArtifacts.hiddenParams) ? sastArtifacts.hiddenParams : []
    const gadgets = Array.isArray(sastArtifacts.gadgets) ? sastArtifacts.gadgets : []
    const lastFindingId = findings.length ? String(findings[findings.length - 1]?.id || "") : ""
    const lastRequestId = requests.length ? String(requests[requests.length - 1]?.id || "") : ""
    const lastRequestAttacks = requests.length
        ? (Array.isArray(requests[requests.length - 1]?.attacks) ? requests[requests.length - 1].attacks : [])
        : []
    const lastAttackId = lastRequestAttacks.length
        ? String(lastRequestAttacks[lastRequestAttacks.length - 1]?.id || "")
        : ""
    const lastRouteArtifactId = routes.length ? String(routes[routes.length - 1]?.id || "") : ""
    const lastEndpointArtifactId = endpoints.length ? String(endpoints[endpoints.length - 1]?.id || "") : ""
    const lastGraphqlArtifactId = graphql.length ? String(graphql[graphql.length - 1]?.id || "") : ""
    const lastSurfaceArtifactId = surfaces.length ? String(surfaces[surfaces.length - 1]?.id || "") : ""
    const lastHiddenParamArtifactId = hiddenParams.length ? String(hiddenParams[hiddenParams.length - 1]?.id || "") : ""
    const lastGadgetArtifactId = gadgets.length ? String(gadgets[gadgets.length - 1]?.id || "") : ""
    const extraEngines = sortEngines(
        (Array.isArray(extraEnginesPresent) ? extraEnginesPresent : [])
            .map((engine) => normalizeEngineName(engine))
            .filter(Boolean)
    )
    return [
        scanResult.engine || "",
        scanResult.scanId || "",
        scanResult.host || "",
        scanResult.finishedAt || scanResult.finished || "",
        findings.length,
        requests.length,
        runtimeEvents.length,
        files.length,
        routes.length,
        endpoints.length,
        graphql.length,
        surfaces.length,
        hiddenParams.length,
        gadgets.length,
        Number(scanResult?.stats?.attacksCount || 0),
        Number(scanResult?.stats?.findingsCount || 0),
        lastFindingId,
        lastRequestId,
        lastAttackId,
        lastRouteArtifactId,
        lastEndpointArtifactId,
        lastGraphqlArtifactId,
        lastSurfaceArtifactId,
        lastHiddenParamArtifactId,
        lastGadgetArtifactId,
        extraEngines.join(","),
        buildPreviousAnalysisSignature(previousAnalysis),
        buildRelatedScansSignature(relatedScans)
    ].join("|")
}

function extractResponseText(responseBody) {
    if (typeof responseBody === "string") return responseBody.slice(0, 4096)
    if (!responseBody || typeof responseBody !== "object") return ""
    if (typeof responseBody.preview === "string") return responseBody.preview.slice(0, 4096)
    if (typeof responseBody.text === "string") return responseBody.text.slice(0, 4096)
    if (typeof responseBody.message === "string") return responseBody.message.slice(0, 4096)
    if (typeof responseBody.error === "string") return responseBody.error.slice(0, 4096)
    if (typeof responseBody.raw === "string") return responseBody.raw.slice(0, 4096)
    return ""
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
    if (splitCrlf >= 0) {
        return rawRequest.slice(splitCrlf + 4)
    }
    const splitLf = rawRequest.indexOf("\n\n")
    if (splitLf >= 0) {
        return rawRequest.slice(splitLf + 2)
    }
    return ""
}

function parseQueryParamNames(url, hostHint = null) {
    if (!url) return []
    try {
        const parsed = new URL(String(url), hostHint ? `http://${String(hostHint)}` : undefined)
        const names = new Set()
        for (const key of parsed.searchParams.keys()) {
            const trimmed = String(key || "").trim()
            if (trimmed) names.add(trimmed)
        }
        return Array.from(names).sort((a, b) => a.localeCompare(b))
    } catch (_) {
        return []
    }
}

function parseFormBodyParamNames(body = "") {
    if (typeof body !== "string" || !body.length) return []
    try {
        const params = new URLSearchParams(body)
        const names = new Set()
        for (const key of params.keys()) {
            const trimmed = String(key || "").trim()
            if (trimmed) names.add(trimmed)
        }
        return Array.from(names).sort((a, b) => a.localeCompare(b))
    } catch (_) {
        return []
    }
}

function parseJsonBodyParamNames(body = "") {
    if (typeof body !== "string" || !body.length) return []
    try {
        const parsed = JSON.parse(body)
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return []
        return Object.keys(parsed)
            .map((key) => String(key || "").trim())
            .filter(Boolean)
            .sort((a, b) => a.localeCompare(b))
    } catch (_) {
        return []
    }
}

function extractParamNamesFromRequest(originalRequest = {}, hostHint = null) {
    const names = new Set()
    const requestUrl = originalRequest?.url || null
    parseQueryParamNames(requestUrl, hostHint).forEach((name) => names.add(name))

    const headers = Array.isArray(originalRequest?.headers) ? originalRequest.headers : []
    const contentType = String(getHeaderValue(headers, "content-type") || "").toLowerCase()
    const body = extractRawBody(originalRequest?.raw || "")
    if (body) {
        if (contentType.includes("application/x-www-form-urlencoded")) {
            parseFormBodyParamNames(body).forEach((name) => names.add(name))
        } else if (contentType.includes("application/json") || body.startsWith("{")) {
            parseJsonBodyParamNames(body).forEach((name) => names.add(name))
        }
    }

    return Array.from(names).sort((a, b) => a.localeCompare(b))
}

function buildPassiveFindingResponseText(finding = {}) {
    const parts = [
        finding?.title,
        finding?.name,
        finding?.category,
        finding?.vulnId,
        finding?.moduleId,
        finding?.ruleId
    ]
    return parts
        .map((part) => String(part || "").trim())
        .filter(Boolean)
        .join(" ")
        .slice(0, 4096)
}

function buildPassiveObservations(scanResult, caps = DEFAULT_CAPS) {
    const maxPassiveObservations = Math.max(1, Number(caps.maxPassiveObservations) || DEFAULT_CAPS.maxPassiveObservations)
    const observations = []
    const truncation = {
        passive: 0
    }
    const hostHint = scanResult?.host || null
    const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []

    for (let reqIdx = 0; reqIdx < requests.length; reqIdx += 1) {
        if (observations.length >= maxPassiveObservations) {
            truncation.passive += (requests.length - reqIdx)
            break
        }
        const request = requests[reqIdx]
        if (!request || typeof request !== "object") continue
        const requestId = toNonEmptyString(request.id) || `req-${reqIdx + 1}`
        const originalRequest = request?.original?.request || {}
        const originalResponse = request?.original?.response || {}
        const fallbackUrl = originalRequest?.url || request?.url || request?.original?.ui_url || null
        const fallbackMethod = normalizeMethod(originalRequest?.method || "GET")
        const routeKey = buildRouteKey({
            url: fallbackUrl,
            method: fallbackMethod,
            host: hostHint
        })
        const routeFamilyKey = buildRouteFamilyKey(routeKey)
        const statusCode = Number(originalResponse?.statusCode ?? originalResponse?.status ?? 0)
        const timeMs = Number(originalResponse?.timeMs ?? originalResponse?.time ?? 0)
        const responseText = extractResponseText(originalResponse?.body)
        const evidenceRefs = normalizeEvidenceRefs([
            {
                type: "request",
                id: requestId,
                loc: {
                    method: fallbackMethod,
                    path: String(routeKey).split("|")[2] || "/"
                }
            }
        ])
        const paramNames = extractParamNamesFromRequest(originalRequest, hostHint)
        const keys = paramNames.length ? paramNames : ["<none>"]
        for (let paramIdx = 0; paramIdx < keys.length; paramIdx += 1) {
            if (observations.length >= maxPassiveObservations) {
                truncation.passive += (keys.length - paramIdx)
                break
            }
            const key = keys[paramIdx]
            observations.push({
                source: "request",
                requestId,
                attackId: `passive-req-${requestId}-${paramIdx + 1}`,
                routeKey,
                routeFamilyKey,
                method: fallbackMethod,
                paramKey: normalizeParamKey(key, "param"),
                rawParam: key === "<none>" ? null : key,
                statusCode,
                timeMs,
                moduleId: null,
                ruleId: null,
                category: null,
                responseText,
                evidenceRefs
            })
        }
    }

    const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
    for (let findingIdx = 0; findingIdx < findings.length; findingIdx += 1) {
        if (observations.length >= maxPassiveObservations) {
            truncation.passive += (findings.length - findingIdx)
            break
        }
        const finding = findings[findingIdx]
        if (!finding || typeof finding !== "object") continue
        const location = finding?.location || {}
        const url = location?.runtimeUrl || location?.url || location?.route || null
        const method = normalizeMethod(location?.method || "GET")
        const routeKey = buildRouteKey({
            url,
            method,
            host: hostHint
        })
        const routeFamilyKey = buildRouteFamilyKey(routeKey)
        const paramNames = []
        const directParam = toNonEmptyString(location?.param)
        if (directParam) {
            paramNames.push(directParam)
        } else {
            parseQueryParamNames(url, hostHint).forEach((param) => paramNames.push(param))
        }
        if (!paramNames.length) {
            paramNames.push("<none>")
        }

        const findingId = toNonEmptyString(finding?.id) || `finding-${findingIdx + 1}`
        const requestId = toNonEmptyString(finding?.evidence?.dast?.requestId)
        const attackId = toNonEmptyString(finding?.evidence?.dast?.attackId)
        const evidenceRefs = normalizeEvidenceRefs([
            {
                type: "finding",
                id: findingId,
                loc: {
                    module: finding?.moduleId || null,
                    rule: finding?.ruleId || null,
                    severity: finding?.severity || null
                }
            },
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
                    module: finding?.moduleId || null,
                    rule: finding?.ruleId || null,
                    method
                }
            } : null
        ])
        const responseText = buildPassiveFindingResponseText(finding)
        const severity = String(finding?.severity || "").toLowerCase()

        for (let paramIdx = 0; paramIdx < paramNames.length; paramIdx += 1) {
            if (observations.length >= maxPassiveObservations) {
                truncation.passive += (paramNames.length - paramIdx)
                break
            }
            const rawParam = paramNames[paramIdx]
            observations.push({
                source: "finding",
                requestId: requestId || findingId,
                attackId: attackId || `passive-finding-${findingId}-${paramIdx + 1}`,
                routeKey,
                routeFamilyKey,
                method,
                paramKey: normalizeParamKey(rawParam, "param"),
                rawParam: rawParam === "<none>" ? null : rawParam,
                statusCode: 0,
                timeMs: 0,
                moduleId: finding?.moduleId || null,
                ruleId: finding?.ruleId || null,
                category: finding?.category || null,
                responseText,
                severity,
                evidenceRefs
            })
        }
    }

    return { observations, truncation }
}

function buildAttackObservations(scanResult, caps = DEFAULT_CAPS) {
    const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []
    const maxAttackObservations = Math.max(1, Number(caps.maxAttackObservations) || DEFAULT_CAPS.maxAttackObservations)
    const observations = []
    const truncation = {
        attacks: 0,
        runtimeEvents: 0,
        candidates: 0,
        patterns: 0
    }

    for (let reqIdx = 0; reqIdx < requests.length; reqIdx += 1) {
        const request = requests[reqIdx]
        if (!request || typeof request !== "object") continue
        const requestId = toNonEmptyString(request.id) || `req-${reqIdx + 1}`
        const originalRequest = request?.original?.request || {}
        const fallbackUrl = originalRequest?.url || request?.url || request?.original?.ui_url || null
        const fallbackMethod = normalizeMethod(originalRequest?.method || "GET")
        const attacks = Array.isArray(request?.attacks) ? request.attacks : []
        for (let attackIdx = 0; attackIdx < attacks.length; attackIdx += 1) {
            if (observations.length >= maxAttackObservations) {
                truncation.attacks += (attacks.length - attackIdx)
                break
            }
            const attack = attacks[attackIdx]
            if (!attack || typeof attack !== "object") continue
            const attackId = toNonEmptyString(attack.id) || `${requestId}-atk-${attackIdx + 1}`
            const attackRequest = attack.request || originalRequest || {}
            const attackResponse = attack.response || {}
            const method = normalizeMethod(attackRequest?.method || fallbackMethod)
            const url = attackRequest?.url || fallbackUrl
            const routeKey = buildRouteKey({
                url,
                method,
                host: scanResult?.host || null
            })
            const routeFamilyKey = buildRouteFamilyKey(routeKey)
            const paramRaw = attack.param || attack?.metadata?.param || attack?.attacked?.name || null
            const paramKey = normalizeParamKey(paramRaw, "param")
            const statusCode = Number(attackResponse?.statusCode ?? attack.statusCode ?? 0)
            const timeMs = Number(attackResponse?.timeMs ?? attack.timeMs ?? 0)
            const responseText = extractResponseText(attackResponse?.body)
            const evidenceRefs = normalizeEvidenceRefs([
                {
                    type: "request",
                    id: requestId,
                    loc: {
                        method,
                        path: String(routeKey).split("|")[2] || "/"
                    }
                },
                {
                    type: "attack",
                    id: attackId,
                    loc: {
                        module: attack.moduleId || attack.moduleName || null,
                        rule: attack.ruleId || attack.ruleName || null,
                        method
                    }
                }
            ])
            observations.push({
                requestId,
                attackId,
                routeKey,
                routeFamilyKey,
                method,
                paramKey,
                rawParam: paramRaw || null,
                statusCode,
                timeMs,
                moduleId: attack.moduleId || null,
                ruleId: attack.ruleId || null,
                category: attack.category || null,
                responseText,
                evidenceRefs
            })
        }
        if (observations.length >= maxAttackObservations) {
            const remainingRequests = requests.length - reqIdx - 1
            if (remainingRequests > 0) {
                truncation.attacks += remainingRequests
            }
            break
        }
    }

    const runtimeEvents = Array.isArray(scanResult?.runtimeEvents) ? scanResult.runtimeEvents : []
    if (runtimeEvents.length > (caps.maxRuntimeEventsInspected || DEFAULT_CAPS.maxRuntimeEventsInspected)) {
        truncation.runtimeEvents = runtimeEvents.length - (caps.maxRuntimeEventsInspected || DEFAULT_CAPS.maxRuntimeEventsInspected)
    }

    return { observations, truncation }
}

function sortEngines(engines = []) {
    const deduped = Array.from(new Set(engines.filter(Boolean)))
    return deduped.sort((a, b) => {
        const aIdx = ENGINE_ORDER.indexOf(a)
        const bIdx = ENGINE_ORDER.indexOf(b)
        if (aIdx >= 0 && bIdx >= 0) return aIdx - bIdx
        if (aIdx >= 0) return -1
        if (bIdx >= 0) return 1
        return a.localeCompare(b)
    })
}

function deriveEnginesPresent(scanResult, extraEnginesPresent = []) {
    const engines = new Set()
    const scanEngine = normalizeEngineName(scanResult?.engine)
    if (scanEngine) engines.add(scanEngine)
    const findings = Array.isArray(scanResult?.findings) ? scanResult.findings : []
    findings.forEach((finding) => {
        const findingEngine = normalizeEngineName(finding?.engine)
        if (findingEngine) engines.add(findingEngine)
    })
    const hasSastArtifacts = Boolean(
        Array.isArray(scanResult?.codeArtifacts?.sast?.routes) && scanResult.codeArtifacts.sast.routes.length
        || Array.isArray(scanResult?.codeArtifacts?.sast?.endpoints) && scanResult.codeArtifacts.sast.endpoints.length
        || Array.isArray(scanResult?.codeArtifacts?.sast?.graphql) && scanResult.codeArtifacts.sast.graphql.length
        || Array.isArray(scanResult?.codeArtifacts?.sast?.surfaces) && scanResult.codeArtifacts.sast.surfaces.length
        || Array.isArray(scanResult?.codeArtifacts?.sast?.hiddenParams) && scanResult.codeArtifacts.sast.hiddenParams.length
        || Array.isArray(scanResult?.codeArtifacts?.sast?.gadgets) && scanResult.codeArtifacts.sast.gadgets.length
    )
    if (hasSastArtifacts) {
        engines.add("SAST")
    }
    if (Array.isArray(extraEnginesPresent)) {
        extraEnginesPresent.forEach((engine) => {
            const normalized = normalizeEngineName(engine)
            if (normalized) engines.add(normalized)
        })
    }
    return sortEngines(Array.from(engines))
}

export function deriveRouteEnginesByFamily(scanResult, relatedScans = []) {
    const map = new Map()
    const addEngineForRoute = ({ engine, url, method, host } = {}) => {
        const normalizedEngine = normalizeEngineName(engine)
        if (!normalizedEngine) return
        const routeKey = buildRouteKey({
            url,
            method: method || "*",
            host: host || null
        })
        const family = buildRouteFamilyKey(routeKey)
        if (!map.has(family)) {
            map.set(family, new Set())
        }
        map.get(family).add(normalizedEngine)
    }
    const consumeScan = (scan) => {
        if (!scan || typeof scan !== "object") return
        const host = scan?.host || null
        const findings = Array.isArray(scan?.findings) ? scan.findings : []
        findings.forEach((finding) => {
            const engine = normalizeEngineName(finding?.engine || scan?.engine)
            const location = finding?.location || {}
            addEngineForRoute({
                engine,
                url: location?.runtimeUrl || location?.url || location?.route || null,
                method: location?.method || "*",
                host
            })
        })
        const scanEngine = normalizeEngineName(scan?.engine) || "DAST"
        const requests = Array.isArray(scan?.requests) ? scan.requests : []
        requests.forEach((record) => {
            const originalRequest = record?.original?.request || {}
            addEngineForRoute({
                engine: scanEngine,
                url: originalRequest?.url || record?.url || null,
                method: originalRequest?.method || "GET",
                host
            })
            const attacks = Array.isArray(record?.attacks) ? record.attacks : []
            attacks.forEach((attack) => {
                const attackRequest = attack?.request || {}
                addEngineForRoute({
                    engine: scanEngine,
                    url: attackRequest?.url || originalRequest?.url || null,
                    method: attackRequest?.method || originalRequest?.method || "GET",
                    host
                })
            })
        })
        const runtimeEvents = Array.isArray(scan?.runtimeEvents) ? scan.runtimeEvents : []
        runtimeEvents.forEach((event) => {
            const eventEngine = normalizeEngineName(event?.engine || scan?.engine || "IAST")
            const routeHint = event?.route
                || event?.url
                || event?.location?.url
                || event?.routing?.runtimeUrl
                || event?.routing?.url
                || null
            const methodHint = event?.method || event?.location?.method || "*"
            addEngineForRoute({
                engine: eventEngine,
                url: routeHint,
                method: methodHint,
                host
            })
        })
        const sastArtifacts = scan?.codeArtifacts?.sast && typeof scan.codeArtifacts.sast === "object"
            ? scan.codeArtifacts.sast
            : {}
        const routeArtifacts = Array.isArray(sastArtifacts.routes) ? sastArtifacts.routes : []
        routeArtifacts.forEach((artifact) => {
            addEngineForRoute({
                engine: "SAST",
                url: artifact?.path || artifact?.routeKey || null,
                method: artifact?.method || "*",
                host
            })
        })
        const endpointArtifacts = Array.isArray(sastArtifacts.endpoints) ? sastArtifacts.endpoints : []
        endpointArtifacts.forEach((artifact) => {
            addEngineForRoute({
                engine: "SAST",
                url: artifact?.resolvedUrl || artifact?.url || artifact?.routeKey || null,
                method: artifact?.method || "GET",
                host
            })
        })
        const graphqlArtifacts = Array.isArray(sastArtifacts.graphql) ? sastArtifacts.graphql : []
        graphqlArtifacts.forEach((artifact) => {
            addEngineForRoute({
                engine: "SAST",
                url: artifact?.resolvedUrl || artifact?.url || artifact?.routeKey || artifact?.pageUrl || null,
                method: artifact?.method || "POST",
                host
            })
        })
        const surfaceArtifacts = Array.isArray(sastArtifacts.surfaces) ? sastArtifacts.surfaces : []
        surfaceArtifacts.forEach((artifact) => {
            addEngineForRoute({
                engine: "SAST",
                url: artifact?.routeKey || artifact?.pageUrl || null,
                method: "*",
                host
            })
        })
        const hiddenParamArtifacts = Array.isArray(sastArtifacts.hiddenParams) ? sastArtifacts.hiddenParams : []
        hiddenParamArtifacts.forEach((artifact) => {
            addEngineForRoute({
                engine: "SAST",
                url: artifact?.routeKey || artifact?.pageUrl || null,
                method: "GET",
                host
            })
        })
        const gadgetArtifacts = Array.isArray(sastArtifacts.gadgets) ? sastArtifacts.gadgets : []
        gadgetArtifacts.forEach((artifact) => {
            addEngineForRoute({
                engine: "SAST",
                url: artifact?.routeKey || artifact?.pageUrl || null,
                method: "*",
                host
            })
        })
    }
    consumeScan(scanResult)
    ;(Array.isArray(relatedScans) ? relatedScans : []).forEach((scan) => consumeScan(scan))
    return map
}

function stableWhyDigest(why = []) {
    if (!Array.isArray(why) || !why.length) return ""
    return why
        .map((entry) => `${entry?.signal || ""}:${entry?.value || ""}`)
        .sort((a, b) => a.localeCompare(b))
        .join("|")
}

function candidateDiffSignature(candidate = {}) {
    const engines = Array.isArray(candidate?.engineSignals)
        ? candidate.engineSignals.map((engine) => String(engine || "")).sort((a, b) => a.localeCompare(b)).join(",")
        : ""
    return [
        Number(candidate?.score || 0),
        String(candidate?.confidence || "low"),
        String(candidate?.id || ""),
        engines,
        stableWhyDigest(candidate?.why || [])
    ].join("|")
}

function applyCandidateDiff(candidates = [], previousAnalysis = null) {
    const result = Array.isArray(candidates) ? candidates.map((candidate) => ({ ...candidate })) : []
    if (!previousAnalysis || typeof previousAnalysis !== "object") {
        return {
            candidates: result,
            diff: null
        }
    }

    const previousCandidates = Array.isArray(previousAnalysis?.candidates) ? previousAnalysis.candidates : []
    const previousByKey = new Map()
    previousCandidates.forEach((candidate) => {
        if (!candidate || typeof candidate !== "object") return
        const key = String(candidate?.suppressKey || candidate?.id || "").trim()
        if (!key) return
        if (!previousByKey.has(key)) {
            previousByKey.set(key, candidate)
        }
    })

    let addedCount = 0
    let changedCount = 0
    let unchangedCount = 0
    const seenKeys = new Set()

    result.forEach((candidate) => {
        const key = String(candidate?.suppressKey || candidate?.id || "").trim()
        if (!key) {
            candidate.diffStatus = "new"
            addedCount += 1
            return
        }
        const previous = previousByKey.get(key)
        if (!previous) {
            candidate.diffStatus = "new"
            addedCount += 1
            seenKeys.add(key)
            return
        }
        seenKeys.add(key)
        const currentSig = candidateDiffSignature(candidate)
        const previousSig = candidateDiffSignature(previous)
        if (currentSig === previousSig) {
            candidate.diffStatus = "unchanged"
            unchangedCount += 1
            return
        }
        candidate.diffStatus = "changed"
        changedCount += 1
    })

    const removedCount = Array.from(previousByKey.keys()).filter((key) => !seenKeys.has(key)).length

    return {
        candidates: result,
        diff: {
            baseScanId: previousAnalysis?.scanId || null,
            baseVersion: previousAnalysis?.version || null,
            baseCandidateCount: previousCandidates.length,
            addedCount,
            changedCount,
            unchangedCount,
            removedCount
        }
    }
}

function patternId(pattern = {}) {
    const payload = [
        pattern.ruleCode || "",
        pattern.routeKey || "",
        pattern.paramKey || "",
        pattern.title || ""
    ].join("|")
    return `pat_${hashHex(payload).slice(0, 24)}`
}

function normalizePatterns(patterns = [], maxPatterns = DEFAULT_CAPS.maxPatterns) {
    const keyed = new Map()
    patterns
        .filter((pattern) => pattern && typeof pattern === "object")
        .forEach((pattern) => {
            const id = patternId(pattern)
            if (!keyed.has(id)) {
                keyed.set(id, {
                    id,
                    ruleCode: pattern.ruleCode || "RULE_UNKNOWN",
                    title: pattern.title || "Suspicious pattern",
                    type: pattern.type || "PATTERN",
                    routeKey: pattern.routeKey || "unknown-host|GET|/",
                    paramKey: pattern.paramKey || "param:<none>",
                    priority: Number(pattern.priority || 0),
                    signals: pattern.signals && typeof pattern.signals === "object" ? pattern.signals : {},
                    evidenceRefs: normalizeEvidenceRefs(pattern.evidenceRefs || [], { maxRefs: 10 })
                })
            }
        })

    return Array.from(keyed.values())
        .sort((a, b) => {
            if (b.priority !== a.priority) return b.priority - a.priority
            return a.id.localeCompare(b.id)
        })
        .slice(0, Math.max(1, Number(maxPatterns) || DEFAULT_CAPS.maxPatterns))
}

function normalizeCoverageEntries(entries = []) {
    const severityOrder = { high: 3, med: 2, low: 1 }
    return Array.from(entries || [])
        .filter((entry) => entry && typeof entry === "object" && entry.code)
        .sort((a, b) => {
            const aSev = severityOrder[String(a.severity || "low").toLowerCase()] || 0
            const bSev = severityOrder[String(b.severity || "low").toLowerCase()] || 0
            if (bSev !== aSev) return bSev - aSev
            const codeCmp = String(a.code).localeCompare(String(b.code))
            if (codeCmp !== 0) return codeCmp
            return String(a.detail || "").localeCompare(String(b.detail || ""))
        })
}

function computeCoverageConfidence({ scanResult, enginesPresent, gaps, limitations }) {
    const severityPenaltyGap = { high: 20, med: 10, low: 5 }
    const severityPenaltyLimitation = { high: 10, med: 5, low: 2 }
    let score = 20 + (enginesPresent.length * 15)
    const totalPlanned = Number(scanResult?.scanStats?.totalJobsPlanned || 0)
    const totalExecuted = Number(scanResult?.scanStats?.totalJobsExecuted || 0)
    if (totalPlanned > 0) {
        const ratio = totalExecuted / totalPlanned
        if (ratio >= 0.7) score += 10
        if (ratio < 0.4) score -= 10
    }
    const runtimeEvents = Array.isArray(scanResult?.runtimeEvents) ? scanResult.runtimeEvents : []
    if (runtimeEvents.length > 0) score += 5
    gaps.forEach((gap) => {
        const sev = String(gap?.severity || "low").toLowerCase()
        score -= severityPenaltyGap[sev] || 5
    })
    limitations.forEach((limitation) => {
        const sev = String(limitation?.severity || "low").toLowerCase()
        score -= severityPenaltyLimitation[sev] || 2
    })
    score = clamp(Math.round(score), 0, 100)
    const confidence = score >= 75 ? "high" : score >= 45 ? "medium" : "low"
    return { confidence, confidenceScore: score }
}

function baseCoverage(enginesPresent = []) {
    const normalizedPresent = sortEngines(enginesPresent)
    const missing = sortEngines(ENGINE_ORDER.filter((engine) => !normalizedPresent.includes(engine)))
    return {
        enginesPresent: normalizedPresent,
        enginesMissing: missing,
        gaps: [],
        limitations: [],
        confidence: "low",
        confidenceScore: 0
    }
}

function runRules(context) {
    const out = {
        patterns: [],
        candidateSeeds: [],
        coverage: {
            gaps: [],
            limitations: []
        },
        discovery: {}
    }
    RULES.forEach((ruleRunner) => {
        try {
            const result = ruleRunner(context)
            if (!result || typeof result !== "object") return
            if (Array.isArray(result.patterns)) {
                out.patterns.push(...result.patterns)
            }
            if (Array.isArray(result.candidateSeeds)) {
                out.candidateSeeds.push(...result.candidateSeeds)
            }
            if (result.coverage && typeof result.coverage === "object") {
                if (Array.isArray(result.coverage.gaps)) {
                    out.coverage.gaps.push(...result.coverage.gaps)
                }
                if (Array.isArray(result.coverage.limitations)) {
                    out.coverage.limitations.push(...result.coverage.limitations)
                }
            }
            if (result.discovery && typeof result.discovery === "object") {
                Object.entries(result.discovery).forEach(([key, value]) => {
                    if (!Array.isArray(value)) return
                    if (!Array.isArray(out.discovery[key])) {
                        out.discovery[key] = []
                    }
                    out.discovery[key].push(...value)
                })
            }
        } catch (err) {
            // analysis is additive; swallow per-rule errors to avoid affecting scan flow
            try { console.warn("[PTK Analysis] rule execution failed", err?.message || err) } catch (_) { }
        }
    })
    return out
}

function normalizeDiscovery(discovery = {}) {
    const iastBuckets = Array.isArray(discovery?.iastBuckets)
        ? discovery.iastBuckets
            .filter((bucket) => bucket && typeof bucket === "object" && bucket.bucket)
            .map((bucket) => ({
                id: bucket.id || null,
                bucket: String(bucket.bucket || "").trim(),
                subtype: bucket.subtype || null,
                subtypes: Array.isArray(bucket.subtypes) ? bucket.subtypes.slice().sort((a, b) => String(a).localeCompare(String(b))) : [],
                legacyFamilies: Array.isArray(bucket.legacyFamilies) ? bucket.legacyFamilies.slice().sort((a, b) => String(a).localeCompare(String(b))) : [],
                routeKey: bucket.routeKey || "unknown-host|GET|/",
                paramKey: bucket.paramKey || "param:<none>",
                priority: Number(bucket.priority || 0),
                severity: bucket.severity || "low",
                hits: Number(bucket.hits || 0),
                sinkId: bucket.sinkId || null,
                sourceKinds: Array.isArray(bucket.sourceKinds) ? bucket.sourceKinds.slice().sort((a, b) => String(a).localeCompare(String(b))) : [],
                dataKinds: Array.isArray(bucket.dataKinds) ? bucket.dataKinds.slice().sort((a, b) => String(a).localeCompare(String(b))) : [],
                trustLevels: Array.isArray(bucket.trustLevels) ? bucket.trustLevels.slice().sort((a, b) => String(a).localeCompare(String(b))) : [],
                trustDecisions: Array.isArray(bucket.trustDecisions) ? bucket.trustDecisions.slice().sort((a, b) => String(a).localeCompare(String(b))) : [],
                crossOrigin: bucket.crossOrigin === true,
                routeControlled: bucket.routeControlled === true,
                sanitizedCount: Number(bucket.sanitizedCount || 0),
                sanitizerIds: Array.isArray(bucket.sanitizerIds) ? bucket.sanitizerIds.slice().sort((a, b) => String(a).localeCompare(String(b))) : [],
                thirdParty: bucket.thirdParty === true,
                authLike: bucket.authLike === true,
                corroboratingEngines: Array.isArray(bucket.corroboratingEngines)
                    ? bucket.corroboratingEngines.slice().sort((a, b) => String(a).localeCompare(String(b)))
                    : [],
                candidateType: bucket.candidateType || "RUNTIME_ANOMALY",
                evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs || [], { maxRefs: 10 })
            }))
            .sort((a, b) => {
                if (b.priority !== a.priority) return b.priority - a.priority
                return `${a.routeKey}|${a.paramKey}|${a.bucket}`.localeCompare(`${b.routeKey}|${b.paramKey}|${b.bucket}`)
            })
        : []

    return {
        iastBuckets
    }
}

function buildAnalysis(scanResult, { caps = DEFAULT_CAPS, extraEnginesPresent = [], previousAnalysis = null, relatedScans = [] } = {}) {
    const enginesPresent = deriveEnginesPresent(scanResult, extraEnginesPresent)
    const enginesDataAvailable = deriveEnginesPresent(scanResult)
    const enginesPresentSet = new Set(enginesPresent)
    const enginesDataAvailableSet = new Set(enginesDataAvailable)
    const routeEnginesByFamily = deriveRouteEnginesByFamily(scanResult, relatedScans)
    const { observations, truncation } = buildAttackObservations(scanResult, caps)
    const { observations: passiveObservations, truncation: passiveTruncation } = buildPassiveObservations(scanResult, caps)
    truncation.passive = Number(passiveTruncation?.passive || 0)
    const analysisObservations = observations.length > 0 ? observations : passiveObservations
    const context = {
        scanResult,
        enginesPresent,
        enginesPresentSet,
        enginesDataAvailable,
        enginesDataAvailableSet,
        attackObservations: observations,
        passiveObservations,
        analysisObservations,
        routeEnginesByFamily,
        truncation
    }
    const ruleOutput = runRules(context)
    const patterns = normalizePatterns(ruleOutput.patterns || [], caps.maxPatterns)
    const coverage = baseCoverage(enginesPresent)
    coverage.gaps = normalizeCoverageEntries(ruleOutput.coverage.gaps || [])
    coverage.limitations = normalizeCoverageEntries(ruleOutput.coverage.limitations || [])
    const scoredCandidates = scoreCandidateSeeds(ruleOutput.candidateSeeds || [], {
        enginesPresent,
        coverage,
        routeEnginesByFamily
    })
    let candidates = scoredCandidates
    if (candidates.length > caps.maxCandidates) {
        truncation.candidates += (candidates.length - caps.maxCandidates)
        candidates = candidates.slice(0, caps.maxCandidates)
    }
    if ((ruleOutput.patterns || []).length > patterns.length) {
        truncation.patterns += ((ruleOutput.patterns || []).length - patterns.length)
    }
    if ((truncation.candidates || 0) > 0 || (truncation.patterns || 0) > 0 || (truncation.passive || 0) > 0) {
        coverage.limitations.push({
            code: "ANALYSIS_INPUT_TRUNCATED",
            severity: "low",
            engine: "ANALYSIS",
            recommendedActionKey: "ACTION_REDUCE_SCAN_SCOPE",
            detail: `Analysis caps applied (candidates=${truncation.candidates || 0}, patterns=${truncation.patterns || 0}, attacks=${truncation.attacks || 0}, passive=${truncation.passive || 0}, runtimeEvents=${truncation.runtimeEvents || 0}).`
        })
    }
    coverage.gaps = normalizeCoverageEntries(coverage.gaps)
    coverage.limitations = normalizeCoverageEntries(coverage.limitations)
    const confidence = computeCoverageConfidence({
        scanResult,
        enginesPresent,
        gaps: coverage.gaps,
        limitations: coverage.limitations
    })
    coverage.confidence = confidence.confidence
    coverage.confidenceScore = confidence.confidenceScore
    const diffAnnotated = applyCandidateDiff(candidates, previousAnalysis)
    const discovery = normalizeDiscovery(ruleOutput.discovery || {})
    return {
        version: ANALYSIS_VERSION,
        scanId: scanResult?.scanId || null,
        coverage,
        patterns,
        candidates: diffAnnotated.candidates,
        diff: diffAnnotated.diff,
        discovery
    }
}

export function applyScanAnalysis(scanResult, { force = false, caps = DEFAULT_CAPS, extraEnginesPresent = [], previousAnalysis = null, relatedScans = [] } = {}) {
    if (!scanResult || typeof scanResult !== "object") return scanResult
    const cacheKey = buildCacheKey(scanResult, extraEnginesPresent, previousAnalysis, relatedScans)
    const currentCache = getCacheKey(scanResult)
    const existingVersion = scanResult?.analysis?.version || null
    if (!force && existingVersion === ANALYSIS_VERSION && currentCache === cacheKey) {
        return scanResult
    }
    const analysis = buildAnalysis(scanResult, { caps, extraEnginesPresent, previousAnalysis, relatedScans })
    scanResult.analysis = analysis
    scanResult.analysisVersion = analysis.version
    setCacheKey(scanResult, cacheKey)
    return scanResult
}

export function ensureScanAnalysis(scanResult, opts = {}) {
    return applyScanAnalysis(scanResult, { force: false, ...opts })
}

export default applyScanAnalysis
