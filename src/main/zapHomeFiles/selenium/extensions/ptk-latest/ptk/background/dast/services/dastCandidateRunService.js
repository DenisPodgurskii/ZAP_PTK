import { PlaywrightMcpClient } from "../../integration/playwrightMcpClient.js"
import { CandidateRunStore } from "../../analysis/candidateRunStore.js"
import { buildPlaywrightCandidateJob } from "../../analysis/playwrightJobBuilder.js"

function normalizeStructuredHeaders(headers) {
    if (!headers) return {}
    if (Array.isArray(headers)) {
        return headers.reduce((acc, item) => {
            const key = String(item?.name || "").trim().toLowerCase()
            if (!key) return acc
            acc[key] = String(item?.value ?? "")
            return acc
        }, {})
    }
    if (typeof headers === "object") {
        return Object.entries(headers).reduce((acc, [name, value]) => {
            const key = String(name || "").trim().toLowerCase()
            if (!key) return acc
            acc[key] = String(value ?? "")
            return acc
        }, {})
    }
    return {}
}

function extractStructuredRequestBody(requestObj = {}) {
    if (!requestObj || typeof requestObj !== "object") return ""
    const requestBody = requestObj?.requestBody
    if (typeof requestBody?.raw === "string") return requestBody.raw
    if (requestBody?.formData && typeof requestBody.formData === "object") {
        try {
            return new URLSearchParams(requestBody.formData).toString()
        } catch (_) { }
    }
    if (typeof requestObj?.body === "string") return requestObj.body
    if (requestObj?.body && typeof requestObj.body === "object") {
        try {
            return JSON.stringify(requestObj.body)
        } catch (_) { }
    }
    return ""
}

export class DastCandidateRunService {
    constructor({
        settings = {},
        getScanResult = () => null,
        getCandidate = () => null,
        getRequestRecordById = () => null,
        playwrightMcpClient = new PlaywrightMcpClient({ settings }),
        candidateRunStore = new CandidateRunStore(),
        buildPlaywrightJob = buildPlaywrightCandidateJob,
        fetchImpl = (...args) => fetch(...args)
    } = {}) {
        this.settings = settings
        this.getScanResult = getScanResult
        this.getCandidate = getCandidate
        this.getRequestRecordById = getRequestRecordById
        this.playwrightMcpClient = playwrightMcpClient
        this.candidateRunStore = candidateRunStore
        this.buildPlaywrightJob = buildPlaywrightJob
        this.fetchImpl = fetchImpl
    }

    _routeFromRouteKey(routeKey) {
        const scanResult = this.getScanResult?.() || {}
        const parts = String(routeKey || "").split("|")
        if (parts.length < 3) {
            return {
                host: scanResult?.host || null,
                method: "GET",
                pathTemplate: "/"
            }
        }
        return {
            host: String(parts[0] || "").trim() || (scanResult?.host || null),
            method: String(parts[1] || "GET").toUpperCase() || "GET",
            pathTemplate: String(parts.slice(2).join("|") || "/")
        }
    }

    _synthesizeRequestSeedFromCandidate(candidate) {
        const route = this._routeFromRouteKey(candidate?.routeKey || "")
        if (!route?.host) return null
        const scheme = String(candidate?.route?.scheme || "http").toLowerCase() === "https" ? "https" : "http"
        const path = String(route.pathTemplate || "/")
            .replace(/:([a-zA-Z0-9_]+)/g, "1")
            .replace(/^([^/])/, "/$1")
        const method = String(route.method || "GET").toUpperCase() || "GET"
        const body = ["POST", "PUT", "PATCH"].includes(method) ? JSON.stringify({}) : ""
        const headers = {}
        if (body) headers["content-type"] = "application/json"
        return {
            method,
            url: `${scheme}://${route.host}${path}`,
            headers,
            body,
            sourceEvidence: null
        }
    }

    _resolveCandidateRequestSeed(candidate) {
        if (!candidate || typeof candidate !== "object") return null
        const refs = Array.isArray(candidate?.evidenceRefs) ? candidate.evidenceRefs : []
        const requestRef = refs.find((ref) => String(ref?.type || "").toLowerCase() === "request" && ref?.id)
        const attackRef = refs.find((ref) => String(ref?.type || "").toLowerCase() === "attack" && ref?.id)
        if (requestRef?.id) {
            const record = this.getRequestRecordById?.(requestRef.id)
            if (record) {
                let attack = null
                if (attackRef?.id) {
                    const attacks = Array.isArray(record?.attacks) ? record.attacks : []
                    attack = attacks.find((item) => String(item?.id || "") === String(attackRef.id)) || null
                }
                const structuredRequest = attack?.request || record?.original?.request || null
                if (structuredRequest && typeof structuredRequest === "object") {
                    const method = String(structuredRequest?.method || attack?.request?.method || "GET").toUpperCase()
                    const url = structuredRequest?.url || attack?.request?.url || null
                    if (url) {
                        return {
                            method,
                            url,
                            headers: normalizeStructuredHeaders(structuredRequest?.headers || structuredRequest?.requestHeaders || []),
                            body: extractStructuredRequestBody(structuredRequest),
                            sourceEvidence: { type: "request", id: requestRef.id }
                        }
                    }
                }
            }
        }
        return this._synthesizeRequestSeedFromCandidate(candidate)
    }

    _mapCandidateRunFromJob(candidateId, jobState = {}, previous = null) {
        const status = String(jobState?.status || previous?.status || "queued").toLowerCase()
        return {
            candidateId: String(candidateId || ""),
            jobId: jobState?.jobId || previous?.jobId || null,
            status,
            acceptedAt: jobState?.acceptedAt || previous?.acceptedAt || null,
            startedAt: jobState?.startedAt || previous?.startedAt || null,
            finishedAt: jobState?.finishedAt || previous?.finishedAt || null,
            requestedAt: previous?.requestedAt || new Date().toISOString(),
            progress: jobState?.progress || previous?.progress || null,
            summary: jobState?.summary || previous?.summary || null,
            observations: Array.isArray(jobState?.observations) ? jobState.observations : (previous?.observations || []),
            artifacts: jobState?.artifacts || previous?.artifacts || null,
            error: jobState?.error || previous?.error || null
        }
    }

    _isMethodAllowedForPlaywright(method) {
        const normalized = String(method || "").trim().toUpperCase()
        return ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(normalized)
    }

    _mapReadinessState({ routeResolved = false, methodAllowed = false, seedQuality = false, baselineReachable = null, lowSignal = false } = {}) {
        let runInPlaywright = "ready"
        let sendToRBuilder = "ready"
        const reasons = []
        if (!routeResolved) reasons.push("ROUTE_UNRESOLVABLE")
        if (!methodAllowed) reasons.push("METHOD_NOT_ALLOWED")
        if (!seedQuality) reasons.push("NO_REQUEST_SEED")
        if (baselineReachable === false) reasons.push("BASELINE_UNREACHABLE")
        if (lowSignal) reasons.push("LOW_SIGNAL_DENSITY")

        if (!routeResolved || !methodAllowed || baselineReachable === false) {
            runInPlaywright = "blocked"
        } else if (!seedQuality || lowSignal) {
            runInPlaywright = "limited"
        }

        if (!routeResolved && !seedQuality) {
            sendToRBuilder = "blocked"
        } else if (!seedQuality) {
            sendToRBuilder = "limited"
        }

        return { runInPlaywright, sendToRBuilder, reasons }
    }

    async _checkPlaywrightBaselineReachability(route = {}, { timeoutMs = 5000, skipNetwork = false } = {}) {
        if (skipNetwork) return null
        const host = String(route?.host || "").trim()
        if (!host) return false
        const scheme = String(route?.scheme || "http").toLowerCase() === "https" ? "https" : "http"
        const origin = `${scheme}://${host}`
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), timeoutMs)
        try {
            const response = await this.fetchImpl(origin, {
                method: "HEAD",
                cache: "no-cache",
                signal: controller.signal
            })
            return response.status > 0 && response.status < 600
        } catch (_) {
            try {
                const fallback = await this.fetchImpl(origin, {
                    method: "GET",
                    cache: "no-cache",
                    signal: controller.signal
                })
                return fallback.status > 0 && fallback.status < 600
            } catch (_) {
                return false
            }
        } finally {
            clearTimeout(timer)
        }
    }

    async computeReadiness(candidate, opts = {}) {
        const route = this._routeFromRouteKey(candidate?.routeKey || "")
        const routeResolved = !!(route?.host && route?.method && route?.pathTemplate)
        const methodAllowed = this._isMethodAllowedForPlaywright(route?.method)
        const seed = this._resolveCandidateRequestSeed(candidate)
        const seedQuality = !!(seed?.method && seed?.url)
        const lowSignal = !Array.isArray(candidate?.why) || candidate.why.length === 0
        const baselineReachable = routeResolved
            ? await this._checkPlaywrightBaselineReachability(route, { timeoutMs: 5000, skipNetwork: opts?.skipNetwork === true })
            : false
        const mapped = this._mapReadinessState({
            routeResolved,
            methodAllowed,
            seedQuality,
            baselineReachable,
            lowSignal
        })
        return {
            runInPlaywright: mapped.runInPlaywright,
            sendToRBuilder: mapped.sendToRBuilder,
            reasons: mapped.reasons,
            details: { routeResolved, methodAllowed, seedQuality, baselineReachable, lowSignal }
        }
    }

    async getCandidatePlaywrightReadiness({ candidateId = null, skipNetwork = false } = {}) {
        const id = String(candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found", candidateId: id }
        try {
            return {
                success: true,
                candidateId: id,
                readiness: await this.computeReadiness(candidate, { skipNetwork })
            }
        } catch (err) {
            return { success: false, candidateId: id, error: err?.message || "candidate_readiness_failed" }
        }
    }

    async runCandidateInPlaywright({ candidateId = null, profile = "smoke", authMode = "reuse_storage_state", constraints = {} } = {}) {
        const id = String(candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found" }
        try {
            const readiness = await this.computeReadiness(candidate, { skipNetwork: false })
            if (readiness?.runInPlaywright === "blocked") {
                return { success: false, candidateId: id, error: "candidate_not_ready_for_playwright_run", readiness }
            }
            const requestSeed = this._resolveCandidateRequestSeed(candidate)
            if (!requestSeed) return { success: false, error: "candidate_request_seed_unavailable" }
            const jobPayload = this.buildPlaywrightJob({
                scanResult: this.getScanResult?.() || {},
                candidate,
                requestSeed,
                profile,
                authMode,
                constraints
            })
            const accepted = await this.playwrightMcpClient.createJob(jobPayload)
            const run = this.candidateRunStore.upsert(id, this._mapCandidateRunFromJob(id, {
                ...accepted,
                jobId: accepted?.jobId || jobPayload.jobId,
                status: accepted?.status || "queued",
                acceptedAt: accepted?.acceptedAt || new Date().toISOString()
            }))
            return { success: true, candidateId: id, run, readiness }
        } catch (err) {
            return { success: false, candidateId: id, error: err?.message || "playwright_mcp_run_failed" }
        }
    }

    async getCandidatePlaywrightRun({ candidateId = null } = {}) {
        const id = String(candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const existing = this.candidateRunStore.get(id)
        if (!existing || !existing.jobId) {
            return { success: false, error: "candidate_run_not_found", candidateId: id }
        }
        const status = String(existing?.status || "").toLowerCase()
        if (status !== "queued" && status !== "running") {
            return { success: true, candidateId: id, run: existing }
        }
        try {
            const jobState = await this.playwrightMcpClient.getJob(existing.jobId)
            const next = this.candidateRunStore.applyJobState({
                ...jobState,
                jobId: jobState?.jobId || existing.jobId
            }, id) || this.candidateRunStore.get(id)
            return { success: true, candidateId: id, run: next }
        } catch (err) {
            const failed = this.candidateRunStore.upsert(id, {
                ...existing,
                status: "failed",
                error: err?.message || "playwright_mcp_poll_failed"
            })
            return { success: true, candidateId: id, run: failed }
        }
    }
}

export default DastCandidateRunService
