import CryptoES from "../../packages/crypto-es/index.js"
import {
    buildRouteFamilyKey,
    buildRouteKey,
    normalizeEngineName,
    normalizeMethod,
    normalizeParamKey,
    splitRouteKey
} from "./canonicalize.js"
import { normalizeEvidenceRefs } from "./evidenceRefs.js"
import { scoreCandidateSeeds } from "./scoring.js"
import { resolveFindingTaxonomy } from "../common/resolveFindingTaxonomy.js"
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
import { buildApiExplorer } from "./apiExplorerBuilder.js"
import { buildAttackSurfaceRecommendations } from "./attackSurfaceRecommendations.js"
import { validateScanAnalysisV1 } from "./scanAnalysisSchema.js"

export const ANALYSIS_VERSION = "1.7.9"

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

function uniqueRouteKeys(values = []) {
    const result = []
    const seen = new Set()
    ;(Array.isArray(values) ? values : []).forEach((value) => {
        const normalized = toNonEmptyString(value)
        if (!normalized || seen.has(normalized)) return
        seen.add(normalized)
        result.push(normalized)
    })
    return result
}

function collectLocationUrlCandidates(location = {}) {
    const candidates = []
    const addCandidate = (value) => {
        if (Array.isArray(value)) {
            value.forEach(addCandidate)
            return
        }
        const normalized = toNonEmptyString(value)
        if (normalized) {
            candidates.push(normalized)
        }
    }
    if (!location || typeof location !== "object") return []
    addCandidate(location?.runtimeUrl)
    addCandidate(location?.url)
    addCandidate(location?.pageUrl)
    addCandidate(location?.route)
    addCandidate(location?.runtimeUrls)
    addCandidate(location?.pageUrls)
    addCandidate(location?.urls)
    addCandidate(location?.observedUrls)
    return uniqueRouteKeys(candidates)
}

function buildLocationRouteKeys(location = {}, { method = "GET", host = null } = {}) {
    const urls = collectLocationUrlCandidates(location)
    if (!urls.length) {
        return [buildRouteKey({
            url: location?.runtimeUrl || location?.url || location?.pageUrl || location?.route || null,
            method,
            host
        })]
    }
    return uniqueRouteKeys(urls.map((url) => buildRouteKey({ url, method, host })))
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
            const sastArtifacts = scan?.codeArtifacts?.sast && typeof scan.codeArtifacts.sast === "object"
                ? scan.codeArtifacts.sast
                : {}
            return [
                scan?.scanId || "",
                normalizeEngineName(scan?.engine) || "",
                scan?.host || "",
                scan?.tabId ?? "",
                scan?.finishedAt || scan?.finished || scan?.startedAt || "",
                Array.isArray(scan?.findings) ? scan.findings.length : 0,
                Array.isArray(scan?.requests) ? scan.requests.length : 0,
                Array.isArray(scan?.runtimeEvents) ? scan.runtimeEvents.length : 0,
                Array.isArray(sastArtifacts?.routes) ? sastArtifacts.routes.length : 0,
                Array.isArray(sastArtifacts?.endpoints) ? sastArtifacts.endpoints.length : 0,
                Array.isArray(sastArtifacts?.graphql) ? sastArtifacts.graphql.length : 0,
                Array.isArray(sastArtifacts?.surfaces) ? sastArtifacts.surfaces.length : 0,
                Array.isArray(sastArtifacts?.hiddenParams) ? sastArtifacts.hiddenParams.length : 0,
                Array.isArray(sastArtifacts?.gadgets) ? sastArtifacts.gadgets.length : 0
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
    const recon = Array.isArray(scanResult?.recon) ? scanResult.recon : []
    for (let reconIdx = 0; reconIdx < recon.length; reconIdx += 1) {
        if (observations.length >= maxPassiveObservations) {
            truncation.passive += (recon.length - reconIdx)
            break
        }
        const observation = recon[reconIdx]
        if (!observation || typeof observation !== "object") continue
        const location = observation?.location || {}
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
        const observationId = toNonEmptyString(observation?.id) || `recon-${reconIdx + 1}`
        const requestId = toNonEmptyString(observation?.evidence?.dast?.requestId)
        const attackId = toNonEmptyString(observation?.evidence?.dast?.attackId)
        const evidenceRefs = normalizeEvidenceRefs([
            {
                type: "recon",
                id: observationId,
                loc: {
                    module: observation?.moduleId || null,
                    rule: observation?.ruleId || null,
                    reconKind: observation?.reconKind || null
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
                    module: observation?.moduleId || null,
                    rule: observation?.ruleId || null,
                    method
                }
            } : null
        ])
        const responseText = buildPassiveFindingResponseText(observation)
        const severity = String(observation?.severity || "").toLowerCase()

        for (let paramIdx = 0; paramIdx < paramNames.length; paramIdx += 1) {
            if (observations.length >= maxPassiveObservations) {
                truncation.passive += (paramNames.length - paramIdx)
                break
            }
            const rawParam = paramNames[paramIdx]
            observations.push({
                source: "recon",
                requestId: requestId || observationId,
                attackId: attackId || `recon-${observationId}-${paramIdx + 1}`,
                routeKey,
                routeFamilyKey,
                method,
                paramKey: normalizeParamKey(rawParam, "param"),
                rawParam: rawParam === "<none>" ? null : rawParam,
                statusCode: 0,
                timeMs: 0,
                moduleId: observation?.moduleId || null,
                ruleId: observation?.ruleId || null,
                category: observation?.category || null,
                responseText,
                severity,
                outputKind: observation?.outputKind || "recon",
                reconKind: observation?.reconKind || null,
                uiSurface: observation?.uiSurface || null,
                evidenceRefs
            })
        }
    }

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
                    title: finding?.title || finding?.ruleName || null,
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
                outputKind: attack.outputKind || null,
                reconKind: attack.reconKind || null,
                uiSurface: attack.uiSurface || null,
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
            buildLocationRouteKeys(location, {
                method: location?.method || "*",
                host
            }).forEach((routeKey) => {
                const routeParts = splitRouteKey(routeKey)
                addEngineForRoute({
                    engine,
                    url: routeParts?.pathTemplate || location?.runtimeUrl || location?.url || location?.route || null,
                    method: routeParts?.method || location?.method || "*",
                    host: routeParts?.host || host
                })
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

function compareAnalysisCandidates(a = {}, b = {}) {
    const scoreDelta = Number(b?.score || 0) - Number(a?.score || 0)
    if (scoreDelta !== 0) return scoreDelta
    const confidenceDelta = Number(b?.confidenceRank || 0) - Number(a?.confidenceRank || 0)
    if (confidenceDelta !== 0) return confidenceDelta
    const titleCmp = String(a?.title || "").localeCompare(String(b?.title || ""))
    if (titleCmp !== 0) return titleCmp
    const routeCmp = String(a?.routeKey || "").localeCompare(String(b?.routeKey || ""))
    if (routeCmp !== 0) return routeCmp
    const paramCmp = String(a?.paramKey || "").localeCompare(String(b?.paramKey || ""))
    if (paramCmp !== 0) return paramCmp
    const ruleCmp = String(a?.createdByRule || "").localeCompare(String(b?.createdByRule || ""))
    if (ruleCmp !== 0) return ruleCmp
    return String(a?.id || "").localeCompare(String(b?.id || ""))
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
    result.sort(compareAnalysisCandidates)

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

function routePathFromRouteKey(routeKey = "unknown-host|GET|/") {
    const parts = String(routeKey || "").split("|")
    return parts.length >= 3 ? parts.slice(2).join("|") || "/" : "/"
}

function normalizeRoutePath(path = "/") {
    return String(path || "/")
        .trim()
        .replace(/[?#].*$/, "")
        .toLowerCase() || "/"
}

function isLikelyStaticAssetPath(path = "/") {
    const normalized = normalizeRoutePath(path)
    if (!normalized || normalized === "/") return false
    if (/^\/(?:assets?|static|public|dist|build|i18n|locales|translations?|lang|fonts?|images?|img|icons?|css|js|scripts?|styles?|vendor|media)\//.test(normalized)) {
        return true
    }
    if (/\/(?:assets?|static|public|dist|build|i18n|locales|translations?|lang|fonts?|images?|img|icons?|css|js|scripts?|styles?|vendor|media)\//.test(normalized)) {
        return true
    }
    if (/\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|pdf|txt)$/.test(normalized)) {
        return true
    }
    if (/\/(?:manifest\.json|asset-manifest\.json|site\.webmanifest)$/.test(normalized)) {
        return true
    }
    if (/\.json$/.test(normalized) && /\/(?:assets?|i18n|locales|translations?|lang|public|static|dist|build)\//.test(normalized)) {
        return true
    }
    return false
}

function isLikelyStaticAssetRouteKey(routeKey = "unknown-host|GET|/") {
    return isLikelyStaticAssetPath(routePathFromRouteKey(routeKey))
}

function isDastOnlyCandidate(candidate = {}) {
    const engineSignals = Array.isArray(candidate?.engineSignals)
        ? candidate.engineSignals.map((engine) => normalizeEngineName(engine)).filter(Boolean)
        : []
    return !engineSignals.length || engineSignals.every((engine) => engine === "DAST")
}

function shouldSuppressStaticAssetAnalysisEntry(entry = {}) {
    const path = routePathFromRouteKey(entry?.routeKey || "unknown-host|GET|/")
    if (!isLikelyStaticAssetPath(path)) return false
    const type = String(entry?.type || "").trim().toUpperCase()
    const rule = String(entry?.createdByRule || entry?.ruleCode || "").trim().toUpperCase()
    if (entry?.createdByRule && !isDastOnlyCandidate(entry)) return false
    if (rule === "R3_AUTH_SESSION_DRIFT" || rule === "R8_INCONSISTENT_RESOURCE_BEHAVIOR") return true
    return type === "AUTH_SESSION_DRIFT" || type === "AUTHZ_INCONSISTENCY" || type === "RESOURCE_BEHAVIOR_DRIFT"
}

function filterStaticAssetAnalysisEntries(entries = []) {
    return (Array.isArray(entries) ? entries : []).filter((entry) => !shouldSuppressStaticAssetAnalysisEntry(entry))
}

function extractParamName(paramKey = null) {
    const raw = toNonEmptyString(paramKey)
    if (!raw) return null
    const splitIdx = raw.indexOf(":")
    if (splitIdx < 0) return raw
    const value = raw.slice(splitIdx + 1).trim()
    return value || null
}

function uniqueSortedStrings(values = []) {
    return Array.from(new Set((Array.isArray(values) ? values : []).map((value) => String(value || "").trim()).filter(Boolean)))
        .sort((a, b) => a.localeCompare(b))
}

function humanizeAnalysisToken(value, fallback = "Recon Observation") {
    const raw = toNonEmptyString(value)
    if (!raw) return fallback
    return raw
        .replace(/[_-]+/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .replace(/\b\w/g, (char) => char.toUpperCase())
}

function inferInventoryKind(name = "") {
    const normalized = String(name || "").trim().toLowerCase()
    if (!normalized) return null
    if (/(^|_)(uuid|guid)($|_)/.test(normalized)) return "uuid"
    if (normalized.includes("slug")) return "slug"
    if (normalized.includes("email")) return "email"
    if (/(tenant|org|organisation|organization|project|team|workspace)/.test(normalized)) return "tenant_scope"
    if (/(user|account|customer|member|owner|profile)/.test(normalized)) return "principal_id"
    if (/(role|permission|scope|privilege|entitlement|feature|flag)/.test(normalized)) return "access_control"
    if (/(file|object|bucket|blob|path|upload|asset|attachment|document|image|avatar|key)/.test(normalized)) return "object_key"
    if (/(^|_)(id)($|_)/.test(normalized) || normalized.endsWith("id")) return "identifier"
    return null
}

function buildSuggestedChecksFromBucket(bucket = {}) {
    const checks = []
    if (bucket.authLike) checks.push("authz_diff")
    if (bucket.routeControlled) checks.push("route_guard_bypass")
    if (bucket.crossOrigin) checks.push("cross_origin_review")
    if (bucket.bucket === "client_execution") checks.push("dom_xss_review")
    if (bucket.bucket === "cross_context_messaging") checks.push("postmessage_review")
    if (bucket.bucket === "client_authz_and_state") checks.push("client_authz_review")
    if (String(bucket.sinkId || "").includes("websocket")) checks.push("websocket_review")
    return checks.length ? uniqueSortedStrings(checks) : ["manual_review"]
}

function buildSuggestedChecksFromCandidate(candidate = {}) {
    const checks = []
    const type = String(candidate?.type || "").trim().toUpperCase()
    const rule = String(candidate?.createdByRule || "").trim().toUpperCase()
    const title = String(candidate?.title || "").trim().toLowerCase()
    const paramName = String(extractParamName(candidate?.paramKey) || "").trim().toLowerCase()
    const routePath = String(routePathFromRouteKey(candidate?.routeKey) || "").trim().toLowerCase()
    const objectLikeParam = /(uuid|guid|tenant|org|organization|project|team|workspace|account|customer|user|member|owner|profile|file|document|asset|blob|bucket|slug|email|id)$/.test(paramName)
    const authLikeTitle = /(auth|role|privilege|admin|permission|session|tenant)/.test(`${title} ${routePath}`)

    if (type === "AUTHZ_INCONSISTENCY" || type === "AUTH_SESSION_DRIFT" || rule.includes("AUTH") || authLikeTitle) {
        checks.push("authz_diff")
    }
    if (type === "RESOURCE_BEHAVIOR_DRIFT") {
        checks.push("response_diff_review")
    }
    if (type === "PARAM_CLUSTER" || objectLikeParam) {
        checks.push("object_id_review")
    }
    if (objectLikeParam || type === "AUTHZ_INCONSISTENCY") {
        checks.push("id_swap_review")
    }
    if (type.includes("ERROR") || /(5xx|error|exception|stack trace)/.test(title)) {
        checks.push("error_path_review")
    }
    if (type.includes("LATENCY")) {
        checks.push("timing_review")
    }
    if (type === "PASSIVE_FINDING_CLUSTER") {
        checks.push("active_validation")
    }
    if (type.includes("TEMPLATE_RENDER") || /(template|render|ssti)/.test(title)) {
        checks.push("ssti_review")
    }
    if (type.includes("GRAPHQL") || /graphql/.test(title)) {
        checks.push("graphql_review")
    }
    if (type === "CODE_HOTSPOT") {
        checks.push("code_hotspot_review")
    }
    return checks.length ? uniqueSortedStrings(checks) : ["manual_review"]
}

function buildReconObservationRouteShape(observation = {}, hostHint = null) {
    const location = observation?.location && typeof observation.location === "object" ? observation.location : {}
    const method = normalizeMethod(location?.method || "GET")
    const routeKey = buildRouteKey({
        url: location?.runtimeUrl || location?.url || location?.route || null,
        method,
        host: hostHint
    })
    return {
        routeKey,
        path: routePathFromRouteKey(routeKey),
        method
    }
}

function extractReconObservationParamKey(observation = {}, hostHint = null) {
    const location = observation?.location && typeof observation.location === "object" ? observation.location : {}
    const directParam = toNonEmptyString(location?.param)
    if (directParam) {
        return normalizeParamKey(directParam, "param")
    }
    const url = location?.runtimeUrl || location?.url || location?.route || null
    const queryNames = parseQueryParamNames(url, hostHint)
    if (queryNames.length) {
        return normalizeParamKey(queryNames[0], "param")
    }
    return "param:<none>"
}

function buildReconObservationEvidenceRefs(observation = {}, { routeKey = "unknown-host|GET|/", method = "GET" } = {}) {
    const observationId = toNonEmptyString(observation?.id)
    const requestId = toNonEmptyString(observation?.evidence?.dast?.requestId)
    const attackId = toNonEmptyString(observation?.evidence?.dast?.attackId)
    return normalizeEvidenceRefs([
        observationId ? {
            type: "recon",
            id: observationId,
            loc: {
                module: observation?.moduleId || null,
                rule: observation?.ruleId || null,
                reconKind: observation?.reconKind || null
            }
        } : null,
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
                module: observation?.moduleId || null,
                rule: observation?.ruleId || null,
                method
            }
        } : null
    ], { maxRefs: 10 })
}

function buildSuggestedChecksFromReconObservation(observation = {}) {
    const checks = []
    const reconKind = String(observation?.reconKind || "").trim().toLowerCase()
    const moduleId = String(observation?.moduleId || "").trim().toLowerCase()
    const ruleId = String(observation?.ruleId || "").trim().toLowerCase()
    const location = observation?.location && typeof observation.location === "object" ? observation.location : {}
    const routeHint = String(location?.runtimeUrl || location?.url || location?.route || "").trim().toLowerCase()
    const routePath = normalizeRoutePath(buildReconObservationRouteShape(observation).path)
    const paramName = String(location?.param || observation?.evidence?.dast?.param || "").trim().toLowerCase()
    const combined = `${reconKind} ${moduleId} ${ruleId} ${routeHint} ${paramName}`
    const authLikeSurface = reconKind === "auth_surface" || /(auth|admin|role|permission|privilege|tenant|oauth|login|logout|session|token)/.test(combined)
    const corsLikeSurface = /(cors|access-control)/.test(combined)
    const staticAssetRoute = isLikelyStaticAssetPath(routePath)
    const objectLikeParam = /(uuid|guid|tenant|org|organization|project|team|workspace|account|customer|user|member|owner|profile|file|document|asset|blob|bucket|slug|email|id)$/.test(paramName)

    if (authLikeSurface && !staticAssetRoute) {
        checks.push("authz_diff")
    }
    if (corsLikeSurface) {
        checks.push("cross_origin_review")
    }
    if (reconKind === "parameter_leads" || objectLikeParam) {
        checks.push("object_id_review")
        checks.push("id_swap_review")
    }
    if (reconKind === "api_inventory" || /graphql/.test(combined)) {
        checks.push("api_review")
    }
    if (reconKind === "source_artifacts" || /(stack|error|sourcemap)/.test(combined)) {
        checks.push("error_path_review")
    }
    if (reconKind === "cache_privacy" && !staticAssetRoute) {
        checks.push("response_diff_review")
    }
    if (reconKind === "environment_hints" || reconKind === "secret_leads") {
        checks.push("manual_review")
    }
    if (reconKind === "route_inventory" && /(admin|debug|internal|private|beta|graphql)/.test(combined)) {
        checks.push("route_guard_bypass")
    }
    return checks.length ? uniqueSortedStrings(checks) : ["manual_review"]
}

function buildReconObservationPriority(observation = {}) {
    const reconKind = String(observation?.reconKind || "").trim().toLowerCase()
    const severity = String(observation?.severity || "").trim().toLowerCase()
    const location = observation?.location && typeof observation.location === "object" ? observation.location : {}
    const combined = `${reconKind} ${observation?.moduleId || ""} ${observation?.ruleId || ""} ${location?.runtimeUrl || location?.url || ""} ${location?.param || ""}`.toLowerCase()
    const routePath = normalizeRoutePath(buildReconObservationRouteShape(observation).path)
    const staticAssetRoute = isLikelyStaticAssetPath(routePath)
    const paramName = String(location?.param || observation?.evidence?.dast?.param || "").trim().toLowerCase()
    const baseByKind = {
        auth_surface: 44,
        parameter_leads: 36,
        environment_hints: 34,
        secret_leads: 34,
        route_inventory: 28,
        api_inventory: 26,
        metadata_inventory: 22,
        source_artifacts: 24,
        cache_privacy: 24
    }
    const severityBoost = {
        critical: 22,
        high: 16,
        medium: 10,
        low: 5,
        info: 0
    }
    let priority = Number(baseByKind[reconKind] || 18) + Number(severityBoost[severity] || 0)
    if (!staticAssetRoute && /(admin|debug|internal|private|tenant|role|permission|privilege|oauth|token|graphql)/.test(combined)) {
        priority += 6
    }
    if (/(uuid|guid|tenant|org|organization|project|team|workspace|account|customer|user|member|owner|profile|file|document|blob|bucket|slug|email|id)/.test(paramName)) {
        priority += 4
    }
    if (staticAssetRoute) {
        priority -= reconKind === "route_inventory" ? 4 : 16
    }
    return clamp(priority, 1, 100)
}

function buildReconObservationTitle(observation = {}) {
    const explicitRule = toNonEmptyString(observation?.ruleName)
    if (explicitRule) return explicitRule
    const explicitModule = toNonEmptyString(observation?.moduleName)
    if (explicitModule) return explicitModule
    return `Recon: ${humanizeAnalysisToken(observation?.reconKind, "Observation")}`
}

function buildReconObservationAttackMapItems(scanResult = {}) {
    const recon = Array.isArray(scanResult?.recon) ? scanResult.recon : []
    const hostHint = scanResult?.host || null
    return recon
        .filter((observation) => observation && typeof observation === "object")
        .map((observation) => {
            const route = buildReconObservationRouteShape(observation, hostHint)
            return {
                id: observation.id || null,
                source: "recon",
                title: buildReconObservationTitle(observation),
                itemType: observation.reconKind || observation.category || "recon_observation",
                routeKey: route.routeKey,
                path: route.path,
                paramKey: extractReconObservationParamKey(observation, hostHint),
                priority: buildReconObservationPriority(observation),
                suggestedChecks: buildSuggestedChecksFromReconObservation(observation),
                evidenceRefs: buildReconObservationEvidenceRefs(observation, route)
            }
        })
}

function buildReconObservationOpportunities(scanResult = {}) {
    const recon = Array.isArray(scanResult?.recon) ? scanResult.recon : []
    const hostHint = scanResult?.host || null
    return recon
        .filter((observation) => observation && typeof observation === "object")
        .map((observation) => {
            const route = buildReconObservationRouteShape(observation, hostHint)
            const priority = buildReconObservationPriority(observation)
            const severity = String(observation?.severity || "").toLowerCase()
            const confidenceRank = priority >= 50 ? 2 : 1
            return {
                id: observation.id || null,
                source: "recon",
                title: buildReconObservationTitle(observation),
                type: observation.reconKind || observation.category || "RECON_OBSERVATION",
                routeKey: route.routeKey,
                path: route.path,
                paramKey: extractReconObservationParamKey(observation, hostHint),
                priority,
                confidence: severity === "high" || severity === "critical" ? "medium" : "low",
                confidenceRank,
                suggestedChecks: buildSuggestedChecksFromReconObservation(observation),
                evidenceRefs: buildReconObservationEvidenceRefs(observation, route)
            }
        })
}

function extractReconObservationParamNames(observation = {}, hostHint = null) {
    const location = observation?.location && typeof observation.location === "object" ? observation.location : {}
    const names = []
    const directParam = toNonEmptyString(location?.param || observation?.evidence?.dast?.param)
    if (directParam) {
        names.push(directParam)
    }
    const url = location?.runtimeUrl || location?.url || location?.route || null
    parseQueryParamNames(url, hostHint).forEach((name) => names.push(name))
    return uniqueSortedStrings(names)
}

function buildOpportunities(scanResult = {}, candidates = [], discovery = {}) {
    const opportunities = []
    ;(Array.isArray(candidates) ? candidates : []).forEach((candidate) => {
        if (!candidate || typeof candidate !== "object") return
        opportunities.push({
            id: candidate.id || null,
            source: "candidate",
            title: candidate.title || "Opportunity",
            type: candidate.type || "RUNTIME_ANOMALY",
            routeKey: candidate.routeKey || "unknown-host|GET|/",
            path: routePathFromRouteKey(candidate.routeKey),
            paramKey: candidate.paramKey || "param:<none>",
            priority: Number(candidate.score || 0),
            confidence: candidate.confidence || "low",
            confidenceRank: Number(candidate.confidenceRank || 1),
            suggestedChecks: buildSuggestedChecksFromCandidate(candidate),
            evidenceRefs: normalizeEvidenceRefs(candidate.evidenceRefs || [], { maxRefs: 10 })
        })
    })
    ;(Array.isArray(discovery?.iastBuckets) ? discovery.iastBuckets : []).forEach((bucket) => {
        if (!bucket || typeof bucket !== "object") return
        opportunities.push({
            id: bucket.id || null,
            source: "iast_bucket",
            title: `Runtime opportunity on ${routePathFromRouteKey(bucket.routeKey)}`,
            type: bucket.candidateType || "RUNTIME_ANOMALY",
            routeKey: bucket.routeKey || "unknown-host|GET|/",
            path: routePathFromRouteKey(bucket.routeKey),
            paramKey: bucket.paramKey || "param:<none>",
            priority: Number(bucket.priority || 0),
            confidence: bucket.severity === "high" ? "medium" : "low",
            confidenceRank: bucket.severity === "high" ? 2 : 1,
            suggestedChecks: buildSuggestedChecksFromBucket(bucket),
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs || [], { maxRefs: 10 })
        })
    })
    return opportunities
        .sort((a, b) => {
            if (b.priority !== a.priority) return b.priority - a.priority
            return `${a.routeKey}|${a.paramKey}|${a.id || ""}`.localeCompare(`${b.routeKey}|${b.paramKey}|${b.id || ""}`)
        })
        .slice(0, 100)
}

function buildAttackMap(scanResult = {}, patterns = [], candidates = [], discovery = {}) {
    const items = []
    ;(Array.isArray(candidates) ? candidates : []).forEach((candidate) => {
        if (!candidate || typeof candidate !== "object") return
        items.push({
            id: candidate.id || null,
            source: "candidate",
            title: candidate.title || "Candidate",
            itemType: candidate.type || "RUNTIME_ANOMALY",
            routeKey: candidate.routeKey || "unknown-host|GET|/",
            path: routePathFromRouteKey(candidate.routeKey),
            paramKey: candidate.paramKey || "param:<none>",
            priority: Number(candidate.score || 0),
            suggestedChecks: buildSuggestedChecksFromCandidate(candidate),
            evidenceRefs: normalizeEvidenceRefs(candidate.evidenceRefs || [], { maxRefs: 10 })
        })
    })
    ;(Array.isArray(patterns) ? patterns : []).forEach((pattern) => {
        if (!pattern || typeof pattern !== "object") return
        items.push({
            id: pattern.id || null,
            source: "pattern",
            title: pattern.title || "Pattern",
            itemType: pattern.type || "PATTERN",
            routeKey: pattern.routeKey || "unknown-host|GET|/",
            path: routePathFromRouteKey(pattern.routeKey),
            paramKey: pattern.paramKey || "param:<none>",
            priority: Number(pattern.priority || 0),
            suggestedChecks: ["manual_review"],
            evidenceRefs: normalizeEvidenceRefs(pattern.evidenceRefs || [], { maxRefs: 10 })
        })
    })
    ;(Array.isArray(discovery?.iastBuckets) ? discovery.iastBuckets : []).forEach((bucket) => {
        if (!bucket || typeof bucket !== "object") return
        items.push({
            id: bucket.id || null,
            source: "iast_bucket",
            title: `${bucket.bucket || "runtime"} on ${routePathFromRouteKey(bucket.routeKey)}`,
            itemType: bucket.bucket || "IAST_BUCKET",
            routeKey: bucket.routeKey || "unknown-host|GET|/",
            path: routePathFromRouteKey(bucket.routeKey),
            paramKey: bucket.paramKey || "param:<none>",
            priority: Number(bucket.priority || 0),
            suggestedChecks: buildSuggestedChecksFromBucket(bucket),
            evidenceRefs: normalizeEvidenceRefs(bucket.evidenceRefs || [], { maxRefs: 10 })
        })
    })
    return {
        items: items
            .sort((a, b) => {
                if (b.priority !== a.priority) return b.priority - a.priority
                return `${a.routeKey}|${a.paramKey}|${a.id || ""}`.localeCompare(`${b.routeKey}|${b.paramKey}|${b.id || ""}`)
            })
            .slice(0, 150),
        total: items.length
    }
}

function buildObjectInventory(scanResult = {}, patterns = [], candidates = [], discovery = {}) {
    const entries = new Map()

    const addEntry = ({ name, routeKey = "unknown-host|GET|/", source = "analysis", evidenceRefs = [] } = {}) => {
        const normalizedName = toNonEmptyString(name)
        if (!normalizedName) return
        const kind = inferInventoryKind(normalizedName)
        if (!kind) return
        const key = `${kind}|${normalizedName.toLowerCase()}`
        if (!entries.has(key)) {
            entries.set(key, {
                id: `objinv_${hashHex(key).slice(0, 24)}`,
                name: normalizedName,
                kind,
                hits: 0,
                routeKeys: new Set(),
                sources: new Set(),
                evidenceRefs: []
            })
        }
        const entry = entries.get(key)
        entry.hits += 1
        entry.routeKeys.add(routeKey || "unknown-host|GET|/")
        entry.sources.add(source)
        normalizeEvidenceRefs(evidenceRefs || [], { maxRefs: 10 }).forEach((ref) => {
            if (entry.evidenceRefs.length >= 10) return
            entry.evidenceRefs.push(ref)
        })
    }

    const requests = Array.isArray(scanResult?.requests) ? scanResult.requests : []
    const hostHint = scanResult?.host || null
    requests.forEach((request) => {
        const originalRequest = request?.original?.request || {}
        const method = normalizeMethod(originalRequest?.method || "GET")
        const routeKey = buildRouteKey({
            url: originalRequest?.url || request?.url || null,
            method,
            host: hostHint
        })
        extractParamNamesFromRequest(originalRequest, hostHint).forEach((name) => {
            addEntry({
                name,
                routeKey,
                source: "request_param",
                evidenceRefs: normalizeEvidenceRefs([{ type: "request", id: request?.id || null }])
            })
        })
        const path = routePathFromRouteKey(routeKey)
        const matches = path.matchAll(/:([A-Za-z0-9_]+)/g)
        for (const match of matches) {
            addEntry({
                name: match[1],
                routeKey,
                source: "route_param",
                evidenceRefs: normalizeEvidenceRefs([{ type: "request", id: request?.id || null }])
            })
        }
    })

    const recon = Array.isArray(scanResult?.recon) ? scanResult.recon : []
    recon.forEach((observation) => {
        const route = buildReconObservationRouteShape(observation, hostHint)
        extractReconObservationParamNames(observation, hostHint).forEach((name) => {
            addEntry({
                name,
                routeKey: route.routeKey,
                source: "recon",
                evidenceRefs: buildReconObservationEvidenceRefs(observation, route)
            })
        })
    })

    ;[...(Array.isArray(patterns) ? patterns : []), ...(Array.isArray(candidates) ? candidates : [])].forEach((entry) => {
        addEntry({
            name: extractParamName(entry?.paramKey),
            routeKey: entry?.routeKey || "unknown-host|GET|/",
            source: "analysis_param",
            evidenceRefs: entry?.evidenceRefs || []
        })
    })

    ;(Array.isArray(discovery?.iastBuckets) ? discovery.iastBuckets : []).forEach((bucket) => {
        addEntry({
            name: extractParamName(bucket?.paramKey),
            routeKey: bucket?.routeKey || "unknown-host|GET|/",
            source: "iast_bucket",
            evidenceRefs: bucket?.evidenceRefs || []
        })
    })

    const sastArtifacts = scanResult?.codeArtifacts?.sast && typeof scanResult.codeArtifacts.sast === "object"
        ? scanResult.codeArtifacts.sast
        : {}
    ;(Array.isArray(sastArtifacts?.endpoints) ? sastArtifacts.endpoints : []).forEach((endpoint) => {
        const routeKey = endpoint?.routeKey || buildRouteKey({
            url: endpoint?.resolvedUrl || endpoint?.url || endpoint?.path || "/",
            method: endpoint?.method || "*",
            host: hostHint
        })
        ;(Array.isArray(endpoint?.paramNames) ? endpoint.paramNames : []).forEach((name) => {
            addEntry({ name, routeKey, source: "sast_endpoint_param" })
        })
        ;(Array.isArray(endpoint?.bodyKeys) ? endpoint.bodyKeys : []).forEach((name) => {
            addEntry({ name, routeKey, source: "sast_endpoint_body" })
        })
    })
    ;(Array.isArray(sastArtifacts?.graphql) ? sastArtifacts.graphql : []).forEach((artifact) => {
        const routeKey = artifact?.routeKey || buildRouteKey({
            url: artifact?.resolvedUrl || artifact?.url || "/graphql",
            method: artifact?.method || "POST",
            host: hostHint
        })
        ;(Array.isArray(artifact?.variableNames) ? artifact.variableNames : []).forEach((name) => {
            addEntry({ name, routeKey, source: "sast_graphql_variable" })
        })
    })
    ;(Array.isArray(sastArtifacts?.hiddenParams) ? sastArtifacts.hiddenParams : []).forEach((artifact) => {
        addEntry({
            name: artifact?.paramName || artifact?.name || null,
            routeKey: artifact?.routeKey || "unknown-host|GET|/",
            source: "sast_hidden_param"
        })
    })

    return {
        identifiers: Array.from(entries.values())
            .map((entry) => ({
                id: entry.id,
                name: entry.name,
                kind: entry.kind,
                hits: entry.hits,
                routeKeys: uniqueSortedStrings(Array.from(entry.routeKeys)),
                sources: uniqueSortedStrings(Array.from(entry.sources)),
                evidenceRefs: normalizeEvidenceRefs(entry.evidenceRefs, { maxRefs: 10 })
            }))
            .sort((a, b) => {
                if (b.hits !== a.hits) return b.hits - a.hits
                return `${a.kind}|${a.name}`.localeCompare(`${b.kind}|${b.name}`)
            })
            .slice(0, 100),
        total: entries.size
    }
}

function correlationThemeConfig(theme = "") {
    switch (theme) {
    case "dom_xss":
        return {
            type: "RUNTIME_ANOMALY",
            patternType: "CROSS_ENGINE_DOM_XSS",
            titlePrefix: "Cross-engine DOM XSS lead",
            manualSteps: [
                "Trace the exact client-side sink path and confirm whether user-controlled input reaches the DOM execution sink in runtime.",
                "Replay the same route with browser-controlled inputs first, then pivot into the code-discovered sink families to confirm exploitability and context.",
                "Prioritize this route above generic recon because both runtime and code evidence support a DOM XSS path."
            ]
        }
    case "auth_surface":
        return {
            type: "AUTHZ_INCONSISTENCY",
            patternType: "CROSS_ENGINE_AUTH_SURFACE",
            titlePrefix: "Cross-engine auth/session lead",
            manualSteps: [
                "Replay the same route or request across anonymous, low-privilege, and privileged contexts and compare status, body, and field-level deltas.",
                "Cross-check whether client-side guards, hidden parameters, or route gates are enforced server-side.",
                "Prioritize session and role transitions where both runtime and code signals point to authz-sensitive behavior."
            ]
        }
    case "template_render":
        return {
            type: "RUNTIME_ANOMALY",
            patternType: "CROSS_ENGINE_TEMPLATE_RENDER",
            titlePrefix: "Cross-engine template/render workflow lead",
            manualSteps: [
                "Replay the save-then-render flow end to end and capture where submitted content is stored, transformed, and later rendered.",
                "Verify whether the same workflow has client-side or server-side rendering assumptions that can be broken with structured payloads.",
                "Prioritize routes where render workflows overlap with code-discovered sinks, templates, or serialization helpers."
            ]
        }
    case "tenant_boundary":
        return {
            type: "AUTHZ_INCONSISTENCY",
            patternType: "CROSS_ENGINE_TENANT_BOUNDARY",
            titlePrefix: "Cross-engine tenant/object boundary lead",
            manualSteps: [
                "Swap tenant, workspace, user, account, and object identifiers across equivalent requests and compare authorization outcomes.",
                "Exercise hidden parameters, route identifiers, and code-discovered scope fields to confirm whether boundaries are only enforced in the client.",
                "Prioritize this route for IDOR and tenant-isolation testing because multiple engines surfaced object or scope signals."
            ]
        }
    case "file_surface":
        return {
            type: "CODE_HOTSPOT",
            patternType: "CROSS_ENGINE_FILE_SURFACE",
            titlePrefix: "Cross-engine file/export surface lead",
            manualSteps: [
                "Replay the upload, export, or file-handling flow with alternate object keys, filenames, content-types, and download targets.",
                "Compare what the browser surfaces, what DAST discovered at runtime, and what code artifacts reveal about hidden storage or export paths.",
                "Prioritize routes where file or export surfaces overlap with auth-sensitive or object-storage behavior."
            ]
        }
    case "graphql_api_surface":
        return {
            type: "CODE_HOTSPOT",
            patternType: "CROSS_ENGINE_GRAPHQL_API_SURFACE",
            titlePrefix: "Cross-engine GraphQL/API surface lead",
            manualSteps: [
                "Replay the same GraphQL or API route with alternate operation names, variables, and object identifiers and compare field-level responses.",
                "Check whether mutations, subscriptions, and persisted queries expose broader capability than the visible UI path suggests.",
                "Prioritize routes where runtime, recon, and code artifacts all surface the same GraphQL or API entrypoint."
            ]
        }
    case "realtime_boundary":
        return {
            type: "RUNTIME_ANOMALY",
            patternType: "CROSS_ENGINE_REALTIME_BOUNDARY",
            titlePrefix: "Cross-engine realtime boundary lead",
            manualSteps: [
                "Replay the realtime handshake and message flow with alternate channels, event names, and identifiers and compare authorization outcomes.",
                "Validate whether websocket, Socket.IO, SSE, WebTransport, or RTC endpoints enforce the same boundary checks as the normal HTTP flow.",
                "Prioritize endpoints where runtime and code evidence both indicate cross-context or realtime trust assumptions."
            ]
        }
    case "trust_boundary":
        return {
            type: "RUNTIME_ANOMALY",
            patternType: "CROSS_ENGINE_TRUST_BOUNDARY",
            titlePrefix: "Cross-engine trust-boundary lead",
            manualSteps: [
                "Inspect cross-origin messaging, postMessage targets, CSP, script loading, and worker/service-worker surfaces on the same route or page family.",
                "Verify whether browser-side origin and trust checks are strict, especially where runtime and code signals indicate wildcard or weak validation.",
                "Prioritize surfaces where trust decisions span multiple contexts, origins, or dynamically loaded code."
            ]
        }
    case "secret_exposure":
        return {
            type: "CODE_HOTSPOT",
            patternType: "CROSS_ENGINE_SECRET_EXPOSURE",
            titlePrefix: "Cross-engine secret exposure lead",
            manualSteps: [
                "Review the route and related assets for tokens, internal hosts, environment hints, debug output, and storage-backed sensitive values.",
                "Confirm whether the exposed material is user-specific, reusable across trust boundaries, or reachable by untrusted origins or channels.",
                "Prioritize cases where recon, runtime, and code evidence all point to the same secret or data exposure surface."
            ]
        }
    case "redirect_flow":
        return {
            type: "RUNTIME_ANOMALY",
            patternType: "CROSS_ENGINE_REDIRECT_FLOW",
            titlePrefix: "Cross-engine redirect flow lead",
            manualSteps: [
                "Replay the same navigation or form flow with alternate destinations, redirect_uri values, and client-controlled route inputs.",
                "Check whether URL, form, or history-based redirects are constrained to trusted routes and whether OAuth or SSO parameters are enforced server-side.",
                "Prioritize flows where runtime redirects and code-discovered navigation sinks overlap on the same route family."
            ]
        }
    default:
        return null
    }
}

function isCorrelationObjectLikeParam(paramName = "") {
    return /(uuid|guid|tenant|org|organisation|organization|project|team|workspace|account|customer|user|member|owner|profile|file|document|asset|blob|bucket|slug|email|id)$/.test(String(paramName || "").trim().toLowerCase())
}

function inferCorrelationThemesFromDescriptor({
    title = "",
    type = "",
    rule = "",
    routeKey = "",
    paramKey = "",
    why = [],
    engine = "",
    vulnId = "",
    category = ""
} = {}) {
    const normalizedTitle = String(title || "").toLowerCase()
    const normalizedType = String(type || "").toLowerCase()
    const normalizedRule = String(rule || "").toLowerCase()
    const normalizedRoute = String(routeKey || "").toLowerCase()
    const paramName = String(extractParamName(paramKey) || "").toLowerCase()
    const whySignals = Array.isArray(why) ? why : []
    const whyCodes = new Set(whySignals.map((entry) => String(entry?.signal || "").toUpperCase()).filter(Boolean))
    const whyValues = whySignals.map((entry) => String(entry?.value || "").toLowerCase()).join(" ")
    const combined = [
        normalizedTitle,
        normalizedType,
        normalizedRule,
        normalizedRoute,
        paramName,
        whyValues,
        String(vulnId || "").toLowerCase(),
        String(category || "").toLowerCase(),
        String(engine || "").toLowerCase()
    ].join(" ")
    const themes = []

    if (
        whyCodes.has("CLIENT_EXECUTION_SINK")
        || /dom xss|client-side execution|innerhtml|outerhtml|srcdoc|appendchild/.test(combined)
        || /\bdom_xss\b/.test(combined)
    ) {
        themes.push("dom_xss")
    }
    if (
        whyCodes.has("AUTH_SESSION_SIGNAL")
        || whyCodes.has("ADMIN_SURFACE_DISCOVERY")
        || /authz|auth\/session|login|session|permission|privilege|role|admin|gated surface|client-side authz/.test(combined)
    ) {
        themes.push("auth_surface")
    }
    if (
        whyCodes.has("SAVE_RENDER_WORKFLOW")
        || /template render|save-then-render|ssti|render workflow|template/.test(combined)
    ) {
        themes.push("template_render")
    }
    if (
        /idor|tenant|workspace|organisation|organization|org|project|team|account|customer|member|owner|profile|cross-user/.test(combined)
        || (isCorrelationObjectLikeParam(paramName) && (/hidden parameter|object id|swap/.test(combined) || whyCodes.has("HIDDEN_PARAM_DISCOVERY")))
    ) {
        themes.push("tenant_boundary")
    }
    if (
        /\b(upload|download|export|attachment|blob|bucket|invoice|signed-url|object-storage|presign|multipart|filename|content-type)\b/.test(combined)
        || /\b(file|document|avatar|image)\b/.test(paramName)
    ) {
        themes.push("file_surface")
    }
    if (
        whyCodes.has("GRAPHQL_OPERATION_DISCOVERY")
        || whyCodes.has("GRAPHQL_MUTATION")
        || whyCodes.has("GRAPHQL_SUBSCRIPTION")
        || whyCodes.has("GRAPHQL_VARIABLE_DISCOVERY")
        || whyCodes.has("GRAPHQL_FIELD_DISCOVERY")
        || /\b(graphql|graphiql|apollo|introspection|operationname|persisted query|mutation|subscription)\b/.test(combined)
    ) {
        themes.push("graphql_api_surface")
    }
    if (
        whyCodes.has("MESSAGE_TRUST_BOUNDARY")
        || /\b(websocket|socket\.io|sockjs|eventsource|sse|webtransport|webrtc|rtcdatachannel|broadcastchannel|messageport|realtime)\b/.test(combined)
    ) {
        themes.push("realtime_boundary")
    }
    if (
        whyCodes.has("MESSAGE_TRUST_BOUNDARY")
        || whyCodes.has("TRUST_BOUNDARY_CROSS_ORIGIN")
        || whyCodes.has("THIRD_PARTY_RUNTIME_RISK")
        || /\b(postmessage|targetorigin|trusted types|trustedtypes|csp|cross-origin|cross origin|third[- ]party|document\.domain|serviceworker|worker script|script loader|origin validation|wildcard origin|wildcard target)\b/.test(combined)
    ) {
        themes.push("trust_boundary")
    }
    if (
        whyCodes.has("DATA_EXPOSURE_SIGNAL")
        || /\b(secret|token|credential|password|api key|private key|jwt|sourcemap|stack trace|internal host|localhost|nonprod|staging|debug log|console leak|clipboard|exfiltration|sensitive storage|info disclosure)\b/.test(combined)
    ) {
        themes.push("secret_exposure")
    }
    if (
        whyCodes.has("CLIENT_NAV_SINK")
        || whyCodes.has("AUTH_FLOW_DISCOVERY")
        || /\b(open[_ ]redirect|redirect uri|redirect_uri|relaystate|oauth|location\.href|location\.assign|location\.replace|window\.open|form action|formaction|history\.pushstate|history\.replacestate|navigation api)\b/.test(combined)
    ) {
        themes.push("redirect_flow")
    }

    return uniqueSortedStrings(themes)
}

function chooseRepresentativeRouteKey(current = null, next = null) {
    if (!current) return next || null
    if (!next) return current
    const currentMethod = String(current).split("|")[1] || ""
    const nextMethod = String(next).split("|")[1] || ""
    if (currentMethod === "*" && nextMethod !== "*") return next
    return current
}

const CORRELATION_THEME_PRIORITY = Object.freeze({
    dom_xss: 100,
    graphql_api_surface: 92,
    realtime_boundary: 88,
    tenant_boundary: 84,
    auth_surface: 80,
    trust_boundary: 74,
    template_render: 70,
    file_surface: 66,
    redirect_flow: 60,
    secret_exposure: 56
})

const CORRELATION_STRONG_THEME_GATING = new Set([
    "secret_exposure",
    "trust_boundary",
    "redirect_flow"
])

function isCorrelationDerivedSignal({ title = "", rule = "" } = {}) {
    const normalizedRule = String(rule || "").trim().toUpperCase()
    if (normalizedRule === "R13_CROSS_ENGINE_CORRELATION") return true
    return /^cross-engine\b/i.test(String(title || "").trim())
}

function buildCorrelationCombinedDescriptor({
    title = "",
    type = "",
    rule = "",
    routeKey = "",
    paramKey = "",
    why = [],
    engine = "",
    vulnId = "",
    category = "",
    sourceKind = ""
} = {}) {
    const whySignals = Array.isArray(why) ? why : []
    const whyCodes = new Set(whySignals.map((entry) => String(entry?.signal || "").toUpperCase()).filter(Boolean))
    const whyValues = whySignals.map((entry) => String(entry?.value || "").toLowerCase()).join(" ")
    const paramName = String(extractParamName(paramKey) || "").toLowerCase()
    const routeParts = splitRouteKey(routeKey)
    const routeSemantic = [
        String(routeParts?.method || "").toLowerCase(),
        String(routeParts?.pathTemplate || routeKey || "").toLowerCase()
    ].filter(Boolean).join(" ")
    const combined = [
        String(title || "").toLowerCase(),
        String(type || "").toLowerCase(),
        String(rule || "").toLowerCase(),
        routeSemantic,
        paramName,
        whyValues,
        String(vulnId || "").toLowerCase(),
        String(category || "").toLowerCase(),
        String(engine || "").toLowerCase(),
        String(sourceKind || "").toLowerCase()
    ].join(" ")
    return {
        whyCodes,
        combined,
        paramName,
        vulnId: String(vulnId || "").toLowerCase(),
        category: String(category || "").toLowerCase(),
        sourceKind: String(sourceKind || "").toLowerCase()
    }
}

function scoreCorrelationSignalStrength(theme = "", descriptor = {}) {
    const {
        whyCodes = new Set(),
        combined = "",
        paramName = "",
        vulnId = "",
        category = "",
        sourceKind = ""
    } = descriptor
    const isRawFinding = sourceKind === "finding"

    switch (theme) {
    case "dom_xss":
        if (whyCodes.has("CLIENT_EXECUTION_SINK") || whyCodes.has("CODE_GADGET_DISCOVERY")) return 3
        if (vulnId === "dom_xss" || category === "xss") return 3
        if (/\b(dom xss|innerhtml|outerhtml|srcdoc|appendchild|domparser|javascript injection)\b/.test(combined)) return isRawFinding ? 3 : 2
        return 0
    case "auth_surface":
        if (whyCodes.has("AUTH_SESSION_SIGNAL") || whyCodes.has("ADMIN_SURFACE_DISCOVERY")) return 3
        if (/(^|[\s_])(auth|login|logout|session|permission|privilege|role|admin|oauth|mfa)([\s_]|$)/.test(combined)) return isRawFinding ? 2 : 1
        if (/\b(auth_session|auth_failures|authorization|broken_access_control)\b/.test(`${category} ${vulnId}`)) return 2
        return 0
    case "template_render":
        if (whyCodes.has("SAVE_RENDER_WORKFLOW")) return 3
        if (/\b(template render|save-then-render|ssti|render workflow|template)\b/.test(combined)) return isRawFinding ? 2 : 1
        return 0
    case "tenant_boundary":
        if (/\b(idor|bola|tenant|workspace|organisation|organization|org|project|team|account|customer|member|owner|profile|cross-user)\b/.test(combined)) return isRawFinding ? 3 : 2
        if (isCorrelationObjectLikeParam(paramName) && (/\b(hidden parameter|object id|swap|scope)\b/.test(combined) || whyCodes.has("HIDDEN_PARAM_DISCOVERY"))) return 2
        return 0
    case "file_surface":
        if (/\b(upload|download|export|attachment|blob|bucket|invoice|signed-url|object-storage|presign|multipart|filename|content-type)\b/.test(combined)) return isRawFinding ? 3 : 2
        if (/\b(file|document|avatar|image)\b/.test(paramName)) return 1
        return 0
    case "graphql_api_surface":
        if (
            whyCodes.has("GRAPHQL_OPERATION_DISCOVERY")
            || whyCodes.has("GRAPHQL_MUTATION")
            || whyCodes.has("GRAPHQL_SUBSCRIPTION")
            || whyCodes.has("GRAPHQL_VARIABLE_DISCOVERY")
            || whyCodes.has("GRAPHQL_FIELD_DISCOVERY")
        ) return 3
        if (/\b(graphql|graphiql|apollo|introspection|operationname|persisted query|mutation|subscription)\b/.test(combined)) return isRawFinding ? 3 : 2
        return 0
    case "realtime_boundary":
        if (whyCodes.has("MESSAGE_TRUST_BOUNDARY")) return 3
        if (/\b(websocket|socket\.io|sockjs|eventsource|sse|webtransport|webrtc|rtcdatachannel|broadcastchannel|messageport|realtime)\b/.test(combined)) return isRawFinding ? 3 : 2
        return 0
    case "trust_boundary":
        if (whyCodes.has("MESSAGE_TRUST_BOUNDARY") || whyCodes.has("TRUST_BOUNDARY_CROSS_ORIGIN") || whyCodes.has("THIRD_PARTY_RUNTIME_RISK")) return 3
        if (/\b(postmessage|targetorigin|trusted types|trustedtypes|csp|cross-origin|cross origin|third[- ]party|document\.domain|serviceworker|worker script|script loader|origin validation|wildcard origin|wildcard target)\b/.test(combined)) return isRawFinding ? 3 : 2
        return 0
    case "secret_exposure":
        if (whyCodes.has("DATA_EXPOSURE_SIGNAL")) return 3
        if (/\b(sensitive_data|sensitive_storage|data_exfiltration|information_disclosure|debug_exposure)\b/.test(`${category} ${vulnId}`)) return 3
        if (/\b(secret|token|credential|password|api key|private key|jwt|sourcemap|stack trace|internal host|nonprod|staging|debug log|console leak|clipboard|exfiltration|sensitive storage|info disclosure)\b/.test(combined)) return isRawFinding ? 2 : 1
        return 0
    case "redirect_flow":
        if (whyCodes.has("CLIENT_NAV_SINK") || whyCodes.has("AUTH_FLOW_DISCOVERY")) return 3
        if (/\b(open_redirect|redirect uri|redirect_uri|relaystate)\b/.test(`${vulnId} ${combined}`)) return 3
        if (/\b(oauth|location\.href|location\.assign|location\.replace|window\.open|form action|formaction|history\.pushstate|history\.replacestate|navigation api)\b/.test(combined)) return isRawFinding ? 2 : 1
        return 0
    default:
        return 0
    }
}

function buildValidCorrelationFindingIdSet(scans = []) {
    const ids = new Set()
    ;(Array.isArray(scans) ? scans : []).forEach((scan) => {
        ;(Array.isArray(scan?.findings) ? scan.findings : []).forEach((finding) => {
            const id = toNonEmptyString(finding?.id)
            if (id) ids.add(id)
        })
    })
    return ids
}

function filterValidCorrelationEvidenceRefs(refs = [], validFindingIds = null) {
    if (!Array.isArray(refs) || !refs.length) return []
    if (!(validFindingIds instanceof Set) || !validFindingIds.size) return refs
    return refs.filter((ref) => {
        if (!ref || typeof ref !== "object") return false
        const type = String(ref?.type || "").trim().toLowerCase()
        if (type !== "finding") return true
        const id = toNonEmptyString(ref?.id)
        if (!id) return false
        return validFindingIds.has(id)
    })
}

function mergeCorrelationEvidence(target = [], refs = [], validFindingIds = null) {
    const combined = [...(Array.isArray(target) ? target : []), ...(Array.isArray(refs) ? refs : [])]
    const filtered = filterValidCorrelationEvidenceRefs(combined, validFindingIds)
    const engines = Array.from(new Set(filtered.map((ref) => inferCorrelationEvidenceEngine(ref)).filter(Boolean)))
    const merged = selectCorrelationEvidenceRefs(filtered, engines, { maxRefs: 48 })
    target.length = 0
    merged.forEach((ref) => target.push(ref))
}

function inferCorrelationEvidenceEngine(ref = {}) {
    const type = String(ref?.type || "").trim().toLowerCase()
    const id = String(ref?.id || "").trim()
    const moduleId = String(ref?.loc?.module || "").trim().toLowerCase()
    const explicitEngine = id.match(/::(DAST|IAST|SAST|SCA)::/i)
    if (explicitEngine) return String(explicitEngine[1] || "").toUpperCase()
    if (/^[a-f0-9]{32,64}:\d{10,14}$/i.test(id)) return "IAST"
    if (type === "request" || type === "attack") return "DAST"
    if (type === "runtimeevent") return "IAST"
    if (/^sast[-_:]/i.test(id) || /^sast[-_]/i.test(moduleId)) return "SAST"
    if (/^iast[-_:]/i.test(id) || /^iast[-_]/i.test(moduleId)) return "IAST"
    if (/^dast[-_:]/i.test(id) || /^spa[-_]/i.test(moduleId) || /^dast[-_]/i.test(moduleId)) return "DAST"
    if (/^sca[-_:]/i.test(id) || /^sca[-_]/i.test(moduleId)) return "SCA"
    return null
}

function selectCorrelationEvidenceRefs(refs = [], engines = [], { maxRefs = 12 } = {}) {
    const limit = Math.max(1, Number(maxRefs) || 12)
    const normalized = normalizeEvidenceRefs(refs, {
        maxRefs: Math.max(limit, Array.isArray(refs) ? refs.length : limit, 48)
    })
    if (normalized.length <= limit) return normalized

    const wantedEngines = new Set((Array.isArray(engines) ? engines : []).map((engine) => normalizeEngineName(engine)).filter(Boolean))
    const selected = []
    const seen = new Set()
    const pushRef = (ref) => {
        if (!ref || selected.length >= limit) return
        const key = `${String(ref?.type || "")}:${String(ref?.id || "")}:${JSON.stringify(ref?.loc || null)}`
        if (seen.has(key)) return
        seen.add(key)
        selected.push(ref)
    }

    wantedEngines.forEach((engine) => {
        const representative = normalized.find((ref) => inferCorrelationEvidenceEngine(ref) === engine)
        pushRef(representative)
    })

    const wantedTypes = Array.from(new Set(normalized.map((ref) => String(ref?.type || "").trim().toLowerCase()).filter(Boolean)))
    wantedTypes.forEach((type) => {
        const representative = normalized.find((ref) => String(ref?.type || "").trim().toLowerCase() === type)
        pushRef(representative)
    })

    normalized.forEach((ref) => pushRef(ref))
    return selected.slice(0, limit)
}

function buildCorrelationInputScans(scanResult = {}, relatedScans = [], currentPatterns = [], currentCandidates = [], discovery = {}) {
    const scans = [
        {
            engine: scanResult?.engine || null,
            findings: Array.isArray(scanResult?.findings) ? scanResult.findings : [],
            analysis: {
                patterns: Array.isArray(currentPatterns) ? currentPatterns : [],
                candidates: Array.isArray(currentCandidates) ? currentCandidates : [],
                discovery: discovery && typeof discovery === "object" ? discovery : {}
            }
        }
    ]
    ;(Array.isArray(relatedScans) ? relatedScans : []).forEach((scan) => {
        if (!scan || typeof scan !== "object") return
        scans.push(scan)
    })
    return scans
}

function buildCrossEngineCorrelationOutput(scanResult = {}, { relatedScans = [], patterns = [], candidates = [], discovery = {} } = {}) {
    const buckets = new Map()
    const inputScans = buildCorrelationInputScans(scanResult, relatedScans, patterns, candidates, discovery)
    const validFindingIds = buildValidCorrelationFindingIdSet(inputScans)
    const appLevelRawThemeSupport = new Map()

    const getAppLevelThemeSupport = (theme) => {
        if (!appLevelRawThemeSupport.has(theme)) {
            appLevelRawThemeSupport.set(theme, new Map())
        }
        return appLevelRawThemeSupport.get(theme)
    }

    const addAppLevelRawThemeSupport = ({ theme, engine, strength = 0, sourceKind = "", evidenceRefs = [] } = {}) => {
        if (String(sourceKind || "").toLowerCase() !== "finding") return
        if (theme !== "dom_xss") return
        const normalizedEngine = normalizeEngineName(engine)
        if (!normalizedEngine || normalizedEngine !== "SAST") return
        if (Number(strength || 0) < 2) return
        const supportByEngine = getAppLevelThemeSupport(theme)
        if (!supportByEngine.has(normalizedEngine)) {
            supportByEngine.set(normalizedEngine, [])
        }
        mergeCorrelationEvidence(supportByEngine.get(normalizedEngine), evidenceRefs, validFindingIds)
    }

    const addSignal = ({ theme, routeKey, paramKey = "param:<none>", title, type, rule, engine, why = [], evidenceRefs = [], vulnId = "", category = "", sourceKind = "" } = {}) => {
        const config = correlationThemeConfig(theme)
        if (!config || !routeKey || isLikelyStaticAssetRouteKey(routeKey)) return
        if (isCorrelationDerivedSignal({ title, rule })) return
        const routeFamilyKey = buildRouteFamilyKey(routeKey)
        const key = `${theme}|${routeFamilyKey}`
        const normalizedEngine = normalizeEngineName(engine) || engine || null
        const strength = scoreCorrelationSignalStrength(theme, buildCorrelationCombinedDescriptor({
            title,
            type,
            rule,
            routeKey,
            paramKey,
            why,
            engine: normalizedEngine,
            vulnId,
            category,
            sourceKind
        }))
        addAppLevelRawThemeSupport({
            theme,
            engine: normalizedEngine,
            strength,
            sourceKind,
            evidenceRefs
        })
        if (!buckets.has(key)) {
            buckets.set(key, {
                theme,
                routeFamilyKey,
                routeKey: routeKey,
                paramKey: paramKey || "param:<none>",
                engines: new Set(),
                strongEngines: new Set(),
                rawFindingEngines: new Set(),
                titles: new Set(),
                rules: new Set(),
                evidenceRefs: [],
                signalCount: 0,
                maxStrength: 0,
                appLevelSupportEngines: new Set()
            })
        }
        const bucket = buckets.get(key)
        bucket.routeKey = chooseRepresentativeRouteKey(bucket.routeKey, routeKey)
        if (paramKey && bucket.paramKey === "param:<none>") {
            bucket.paramKey = paramKey
        }
        if (normalizedEngine) {
            bucket.engines.add(normalizedEngine)
            if (strength >= 2) {
                bucket.strongEngines.add(normalizedEngine)
            }
            if (String(sourceKind || "").toLowerCase() === "finding") {
                bucket.rawFindingEngines.add(normalizedEngine)
            }
        }
        if (title) bucket.titles.add(String(title))
        if (rule) bucket.rules.add(String(rule))
        bucket.signalCount += 1
        bucket.maxStrength = Math.max(bucket.maxStrength, strength)
        mergeCorrelationEvidence(bucket.evidenceRefs, evidenceRefs, validFindingIds)
    }

    inputScans.forEach((scan) => {
        const engine = normalizeEngineName(scan?.engine) || null
        const analysis = scan?.analysis && typeof scan.analysis === "object" ? scan.analysis : {}
        ;(Array.isArray(analysis?.candidates) ? analysis.candidates : []).forEach((candidate) => {
            inferCorrelationThemesFromDescriptor({
                title: candidate?.title,
                type: candidate?.type,
                rule: candidate?.createdByRule,
                routeKey: candidate?.routeKey,
                paramKey: candidate?.paramKey,
                why: candidate?.why,
                engine,
                vulnId: candidate?.vulnId,
                category: candidate?.category
            }).forEach((theme) => {
                addSignal({
                    theme,
                    routeKey: candidate?.routeKey,
                    paramKey: candidate?.paramKey,
                    title: candidate?.title,
                    type: candidate?.type,
                    rule: candidate?.createdByRule,
                    engine,
                    why: candidate?.why,
                    evidenceRefs: candidate?.evidenceRefs,
                    vulnId: candidate?.vulnId,
                    category: candidate?.category,
                    sourceKind: "candidate"
                })
            })
        })
        ;(Array.isArray(analysis?.patterns) ? analysis.patterns : []).forEach((pattern) => {
            inferCorrelationThemesFromDescriptor({
                title: pattern?.title,
                type: pattern?.type,
                rule: pattern?.ruleCode,
                routeKey: pattern?.routeKey,
                paramKey: pattern?.paramKey,
                engine,
                vulnId: pattern?.vulnId,
                category: pattern?.category
            }).forEach((theme) => {
                addSignal({
                    theme,
                    routeKey: pattern?.routeKey,
                    paramKey: pattern?.paramKey,
                    title: pattern?.title,
                    type: pattern?.type,
                    rule: pattern?.ruleCode,
                    engine,
                    evidenceRefs: pattern?.evidenceRefs,
                    vulnId: pattern?.vulnId,
                    category: pattern?.category,
                    sourceKind: "pattern"
                })
            })
        })
        ;(Array.isArray(scan?.findings) ? scan.findings : []).forEach((finding) => {
            resolveFindingTaxonomy({ finding })
            const location = finding?.location && typeof finding.location === "object" ? finding.location : {}
            buildLocationRouteKeys(location, {
                method: location?.method || "GET",
                host: scan?.host || scanResult?.host || null
            }).forEach((routeKey) => {
                inferCorrelationThemesFromDescriptor({
                    title: finding?.title || finding?.ruleName || finding?.name,
                    type: finding?.type,
                    rule: finding?.ruleId,
                    routeKey,
                    paramKey: location?.param ? normalizeParamKey(location.param, "param") : "param:<none>",
                    engine: normalizeEngineName(finding?.engine || engine),
                    vulnId: finding?.vulnId,
                    category: finding?.category
                }).forEach((theme) => {
                    addSignal({
                        theme,
                        routeKey,
                        paramKey: location?.param ? normalizeParamKey(location.param, "param") : "param:<none>",
                        title: finding?.title || finding?.ruleName || finding?.name,
                        type: finding?.type,
                        rule: finding?.ruleId,
                        engine: normalizeEngineName(finding?.engine || engine),
                        evidenceRefs: normalizeEvidenceRefs([{
                            type: "finding",
                            id: finding?.id || null,
                            loc: {
                                module: finding?.moduleId || null,
                                rule: finding?.ruleId || null,
                                title: finding?.title || finding?.ruleName || finding?.name || null,
                                severity: finding?.severity || null,
                                method: location?.method || "GET",
                                param: location?.param || null
                            }
                        }], { maxRefs: 10 }),
                        vulnId: finding?.vulnId,
                        category: finding?.category,
                        sourceKind: "finding"
                    })
                })
            })
        })
    })

    const strongestThemesByRouteFamily = new Map()
    buckets.forEach((bucket) => {
        if (bucket.theme !== "dom_xss") return
        if (!bucket.rawFindingEngines.has("IAST")) return
        if (bucket.maxStrength < 3) return
        const fallbackSupportByEngine = appLevelRawThemeSupport.get(bucket.theme) || new Map()
        const fallbackEngines = Array.from(fallbackSupportByEngine.keys()).filter(Boolean)
        if (!fallbackEngines.length) return
        let addedSupport = false
        fallbackEngines.forEach((engine) => {
            const refs = fallbackSupportByEngine.get(engine) || []
            if (!refs.length) return
            if (bucket.engines.size <= 1 && !bucket.engines.has(engine)) {
                bucket.engines.add(engine)
                bucket.strongEngines.add(engine)
                bucket.signalCount += 1
                addedSupport = true
            }
            if (!bucket.appLevelSupportEngines.has(engine)) {
                bucket.appLevelSupportEngines.add(engine)
                addedSupport = true
            }
            mergeCorrelationEvidence(bucket.evidenceRefs, refs, validFindingIds)
        })
        if (addedSupport) {
            bucket.titles.add("App-level DOM sink corroboration")
        }
    })
    buckets.forEach((bucket) => {
        if (bucket.strongEngines.size < 2) return
        const routeFamilyKey = bucket.routeFamilyKey || ""
        if (!strongestThemesByRouteFamily.has(routeFamilyKey)) {
            strongestThemesByRouteFamily.set(routeFamilyKey, [])
        }
        strongestThemesByRouteFamily.get(routeFamilyKey).push(bucket.theme)
    })

    const patternsOut = []
    const candidateSeeds = []
    buckets.forEach((bucket) => {
        const engines = sortEngines(Array.from(bucket.engines).filter(Boolean))
        if (engines.length < 2) return
        if (CORRELATION_STRONG_THEME_GATING.has(bucket.theme) && bucket.strongEngines.size < 2) return
        const strongerThemes = strongestThemesByRouteFamily.get(bucket.routeFamilyKey || "") || []
        const currentPriority = Number(CORRELATION_THEME_PRIORITY[bucket.theme] || 0)
        const hasStrongerThemeOnSameRoute = bucket.strongEngines.size < 2
            && strongerThemes.some((theme) => Number(CORRELATION_THEME_PRIORITY[theme] || 0) > currentPriority)
        if (hasStrongerThemeOnSameRoute) return
        const config = correlationThemeConfig(bucket.theme)
        const routeParts = splitRouteKey(bucket.routeKey || bucket.routeFamilyKey)
        const evidenceRefs = selectCorrelationEvidenceRefs(filterValidCorrelationEvidenceRefs(bucket.evidenceRefs, validFindingIds), engines, { maxRefs: 12 })
        const supportLabel = Array.from(bucket.titles).slice(0, 3).join(" | ")
        const priority = clamp(42 + (engines.length * 12) + Math.min(18, bucket.signalCount * 3), 1, 100)

        patternsOut.push({
            ruleCode: "R13_CROSS_ENGINE_CORRELATION",
            title: `${config.titlePrefix} on ${routeParts.method} ${routeParts.pathTemplate}`,
            type: config.patternType,
            routeKey: bucket.routeKey || bucket.routeFamilyKey,
            paramKey: bucket.paramKey || "param:<none>",
            priority,
            signals: {
                engines,
                signalCount: bucket.signalCount,
                supportingTitles: Array.from(bucket.titles).slice(0, 5)
            },
            evidenceRefs
        })

        candidateSeeds.push({
            createdByRule: "R13_CROSS_ENGINE_CORRELATION",
            type: config.type,
            title: `${config.titlePrefix} on ${routeParts.method} ${routeParts.pathTemplate}`,
            routeKey: bucket.routeKey || bucket.routeFamilyKey,
            paramKey: bucket.paramKey || "param:<none>",
            engineSignals: engines,
            repeatabilityCount: Math.max(bucket.signalCount, evidenceRefs.length),
            signals: [
                {
                    code: "CROSS_ENGINE_THEME",
                    value: bucket.theme,
                    weight: 16
                },
                {
                    code: "CROSS_ENGINE_SUPPORT",
                    value: engines.join("+"),
                    weight: 26
                },
                bucket.appLevelSupportEngines.size ? {
                    code: "APP_LEVEL_ENGINE_SUPPORT",
                    value: sortEngines(Array.from(bucket.appLevelSupportEngines)).join("+"),
                    weight: 10
                } : null,
                {
                    code: "SUPPORTING_SIGNAL_COUNT",
                    value: bucket.signalCount,
                    weight: Math.min(16, 4 + (bucket.signalCount * 2))
                },
                supportLabel ? {
                    code: "SUPPORTING_ANALYSIS",
                    value: supportLabel,
                    weight: 10
                } : null
            ].filter(Boolean),
            evidenceRefs,
            manualSteps: config.manualSteps.slice()
        })
    })

    return {
        patterns: patternsOut,
        candidateSeeds
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
    const correlationOutput = buildCrossEngineCorrelationOutput(scanResult, {
        relatedScans,
        patterns: ruleOutput.patterns || [],
        candidates: ruleOutput.candidateSeeds || [],
        discovery: ruleOutput.discovery || {}
    })
    if (Array.isArray(correlationOutput?.patterns) && correlationOutput.patterns.length) {
        ruleOutput.patterns.push(...correlationOutput.patterns)
    }
    if (Array.isArray(correlationOutput?.candidateSeeds) && correlationOutput.candidateSeeds.length) {
        ruleOutput.candidateSeeds.push(...correlationOutput.candidateSeeds)
    }
    const patterns = normalizePatterns(filterStaticAssetAnalysisEntries(ruleOutput.patterns || []), caps.maxPatterns)
    const coverage = baseCoverage(enginesPresent)
    coverage.gaps = normalizeCoverageEntries(ruleOutput.coverage.gaps || [])
    coverage.limitations = normalizeCoverageEntries(ruleOutput.coverage.limitations || [])
    const scoredCandidates = scoreCandidateSeeds(filterStaticAssetAnalysisEntries(ruleOutput.candidateSeeds || []), {
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
    const opportunities = buildOpportunities(scanResult, diffAnnotated.candidates, discovery)
    const attackMap = buildAttackMap(scanResult, patterns, diffAnnotated.candidates, discovery)
    const objectInventory = buildObjectInventory(scanResult, patterns, diffAnnotated.candidates, discovery)
    const explorer = buildApiExplorer(scanResult, { relatedScans })
    const recommendations = buildAttackSurfaceRecommendations({
        scanResult,
        context,
        patterns,
        candidates: diffAnnotated.candidates,
        discovery,
        opportunities,
        attackMap,
        objectInventory,
        explorer
    })
    const analysis = {
        version: ANALYSIS_VERSION,
        scanId: scanResult?.scanId || null,
        coverage,
        patterns,
        candidates: diffAnnotated.candidates,
        diff: diffAnnotated.diff,
        discovery,
        attackMap,
        objectInventory,
        opportunities,
        recommendations,
        explorer
    }
    analysis.schemaValidation = validateScanAnalysisV1(analysis)
    return analysis
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
