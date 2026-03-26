import { PlaywrightMcpClient } from "../../integration/playwrightMcpClient.js"
import { CandidateRunStore } from "../../analysis/candidateRunStore.js"
import { buildPlaywrightCandidateJob } from "../../analysis/playwrightJobBuilder.js"
import { ResponseDiffService } from "../../bugbounty/responseDiffService.js"
import { AuthzDiffService } from "../../bugbounty/authzDiffService.js"
import { AuthzDiffRunStore } from "../../bugbounty/authzDiffRunStore.js"
import { ObjectSwapService } from "../../bugbounty/objectSwapService.js"
import { EvidencePackageStore } from "../../bugbounty/evidencePackageStore.js"
import { ReproductionStepBuilder } from "../../bugbounty/reproductionStepBuilder.js"
import { ReportDraftBuilder } from "../../bugbounty/reportDraftBuilder.js"
import { WorkflowOverlayService } from "../../bugbounty/workflowOverlayService.js"
import { WorkflowDiffService } from "../../bugbounty/workflowDiffService.js"

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

function normalizeComparableHeaders(headers) {
    if (!headers) return []
    if (Array.isArray(headers)) {
        return headers
            .map((entry) => ({
                name: String(entry?.name || "").trim(),
                value: String(entry?.value ?? "")
            }))
            .filter((entry) => !!entry.name)
    }
    if (typeof headers === "object") {
        return Object.entries(headers).map(([name, value]) => ({
            name: String(name || "").trim(),
            value: Array.isArray(value) ? value.join(", ") : String(value ?? "")
        })).filter((entry) => !!entry.name)
    }
    return []
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

function cloneValue(value) {
    if (typeof globalThis.structuredClone === "function") {
        try {
            return globalThis.structuredClone(value)
        } catch (_) {
            // fall back to JSON clone
        }
    }
    return JSON.parse(JSON.stringify(value ?? null))
}

function normalizeSessionProfileSummary(profile = {}, relation = "peer") {
    if (!profile || typeof profile !== "object") return null
    return {
        id: profile?.id || null,
        label: String(profile?.label || "").trim() || "session",
        host: String(profile?.host || "").trim() || "",
        notes: String(profile?.notes || "").trim() || "",
        cookieCount: Number(profile?.cookieCount || profile?.snapshot?.cookies?.length || 0),
        relation: String(relation || "peer").trim().toLowerCase() || "peer"
    }
}

function pickFirstResponseArtifact(run = {}) {
    const direct = [
        run?.artifacts?.response,
        run?.artifacts?.lastResponse,
        run?.summary?.response,
        run?.response
    ].find((entry) => entry && typeof entry === "object")
    if (direct) return direct

    const networkResponses = Array.isArray(run?.artifacts?.network?.responses)
        ? run.artifacts.network.responses
        : []
    if (networkResponses.length) return networkResponses[networkResponses.length - 1]

    const networkEntries = Array.isArray(run?.artifacts?.network?.entries)
        ? run.artifacts.network.entries
        : []
    return networkEntries
        .map((entry) => entry?.response)
        .filter((entry) => entry && typeof entry === "object")
        .pop() || null
}

function extractComparableResponseFromRun(run = {}) {
    const response = pickFirstResponseArtifact(run)
    if (!response || typeof response !== "object") return null
    return {
        status: response?.status ?? response?.statusCode ?? null,
        statusCode: response?.statusCode ?? response?.status ?? null,
        headers: normalizeComparableHeaders(response?.headers || response?.responseHeaders || {}),
        body: typeof response?.body === "string"
            ? response.body
            : (typeof response?.text === "string"
                ? response.text
                : (response?.body && typeof response.body === "object"
                    ? JSON.stringify(response.body)
                    : "")),
        url: response?.url || null
    }
}

function buildAuthzDiffRunId() {
    return `authzdiff_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`
}

function sanitizeEvidenceFilename(value = "", fallback = "evidence-package") {
    const normalized = String(value || "").trim().toLowerCase()
    const safe = normalized
        .replace(/[^a-z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "")
    return safe || fallback
}

function normalizeRunStatus(status) {
    return String(status || "queued").trim().toLowerCase()
}

function isTerminalRunStatus(status) {
    return ["completed", "failed", "canceled", "timed_out"].includes(normalizeRunStatus(status))
}

function truncateText(value, maxLength = 2048) {
    const raw = String(value ?? "")
    if (!raw) return ""
    return raw.length > maxLength ? `${raw.slice(0, maxLength - 16)}...[truncated]` : raw
}

function summarizeComparableResponse(response = null) {
    const normalized = response && typeof response === "object" ? response : {}
    return {
        status: normalized?.status ?? normalized?.statusCode ?? null,
        url: normalized?.url || null,
        headers: normalizeComparableHeaders(normalized?.headers || {}),
        body: truncateText(normalized?.body || normalized?.text || "", 4096)
    }
}

function summarizeRequestSeed(requestSeed = null) {
    const seed = requestSeed && typeof requestSeed === "object" ? requestSeed : {}
    return {
        method: String(seed?.method || "GET").toUpperCase(),
        url: seed?.url || null,
        headers: normalizeComparableHeaders(seed?.headers || {}),
        body: truncateText(seed?.body || "", 4096)
    }
}

export class DastCandidateRunService {
    constructor({
        settings = {},
        getScanResult = () => null,
        getCandidate = () => null,
        getRequestRecordById = () => null,
        sessionProfileStore = null,
        playwrightMcpClient = new PlaywrightMcpClient({ settings }),
        candidateRunStore = new CandidateRunStore(),
        authzDiffRunStore = new AuthzDiffRunStore(),
        buildPlaywrightJob = buildPlaywrightCandidateJob,
        responseDiffService = new ResponseDiffService(),
        authzDiffService = null,
        objectSwapService = new ObjectSwapService(),
        evidencePackageStore = new EvidencePackageStore(),
        reproductionStepBuilder = new ReproductionStepBuilder(),
        reportDraftBuilder = new ReportDraftBuilder(),
        workflowOverlayService = new WorkflowOverlayService(),
        workflowDiffService = new WorkflowDiffService(),
        startWorkflowReplay = null,
        onBugBountyStateChanged = null,
        fetchImpl = (...args) => fetch(...args)
    } = {}) {
        this.settings = settings
        this.getScanResult = getScanResult
        this.getCandidate = getCandidate
        this.getRequestRecordById = getRequestRecordById
        this.sessionProfileStore = sessionProfileStore
        this.playwrightMcpClient = playwrightMcpClient
        this.candidateRunStore = candidateRunStore
        this.authzDiffRunStore = authzDiffRunStore
        this.buildPlaywrightJob = buildPlaywrightJob
        this.responseDiffService = responseDiffService
        this.authzDiffService = authzDiffService || new AuthzDiffService({ responseDiffService })
        this.objectSwapService = objectSwapService
        this.evidencePackageStore = evidencePackageStore
        this.reproductionStepBuilder = reproductionStepBuilder
        this.reportDraftBuilder = reportDraftBuilder
        this.workflowOverlayService = workflowOverlayService
        this.workflowDiffService = workflowDiffService
        this.startWorkflowReplay = typeof startWorkflowReplay === "function"
            ? startWorkflowReplay
            : null
        this.onBugBountyStateChanged = typeof onBugBountyStateChanged === "function"
            ? onBugBountyStateChanged
            : null
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
            sessionProfile: jobState?.sessionProfile || previous?.sessionProfile || null,
            objectSwap: jobState?.objectSwap || previous?.objectSwap || null,
            error: jobState?.error || previous?.error || null
        }
    }

    async _startCandidatePlaywrightRun({
        candidateId = null,
        candidate = null,
        profile = "smoke",
        authMode = "reuse_storage_state",
        constraints = {},
        sessionProfile = null,
        objectSwap = null,
        persist = true,
        sessionRelation = "active"
    } = {}) {
        const resolvedCandidateId = String(candidateId || candidate?.id || "").trim()
        const resolvedCandidate = candidate || this.getCandidate?.(resolvedCandidateId)
        if (!resolvedCandidateId) {
            throw new Error("candidate_id_required")
        }
        if (!resolvedCandidate || typeof resolvedCandidate !== "object") {
            throw new Error("candidate_not_found")
        }
        const requestSeed = this._applySessionProfileToRequestSeed(
            this._resolveCandidateRequestSeed(resolvedCandidate),
            sessionProfile
        )
        if (!requestSeed) {
            throw new Error("candidate_request_seed_unavailable")
        }
        const objectSwapResolution = this._applyObjectSwapToRequestSeed(requestSeed, resolvedCandidate, objectSwap)
        const sessionProfileSummary = normalizeSessionProfileSummary(sessionProfile, sessionRelation)
        const jobPayload = this.buildPlaywrightJob({
            scanResult: this.getScanResult?.() || {},
            candidate: resolvedCandidate,
            requestSeed: objectSwapResolution?.requestSeed || requestSeed,
            profile,
            authMode,
            constraints,
            authContext: this._buildPlaywrightAuthContext({
                authMode,
                sessionProfile
            })
        })
        const accepted = await this.playwrightMcpClient.createJob(jobPayload)
        const run = this._mapCandidateRunFromJob(resolvedCandidateId, {
            ...accepted,
            jobId: accepted?.jobId || jobPayload.jobId,
            status: accepted?.status || "queued",
            acceptedAt: accepted?.acceptedAt || new Date().toISOString(),
            sessionProfile: sessionProfileSummary,
            objectSwap: objectSwapResolution?.objectSwap || null
        })
        if (persist) {
            return this.candidateRunStore.upsert(resolvedCandidateId, run)
        }
        return run
    }

    async _pollPlaywrightJobRun(existingRun = {}, candidateId = null) {
        const jobId = String(existingRun?.jobId || "").trim()
        if (!jobId) return existingRun
        if (isTerminalRunStatus(existingRun?.status)) return existingRun
        const resolvedCandidateId = String(candidateId || existingRun?.candidateId || "").trim()
        const jobState = await this.playwrightMcpClient.getJob(jobId)
        return this._mapCandidateRunFromJob(resolvedCandidateId, {
            ...jobState,
            jobId: jobState?.jobId || jobId
        }, existingRun)
    }

    _buildAuthzDiffRequest(candidate = null) {
        const requestSeed = this._resolveCandidateRequestSeed(candidate)
        return {
            method: requestSeed?.method || candidate?.route?.method || "GET",
            url: requestSeed?.url || null,
            candidateId: candidate?.id || null
        }
    }

    _evaluateAuthzDiff(candidate = null, {
        baselineSession = null,
        comparisonSession = null,
        baselineResponse = null,
        comparisonResponse = null,
        objectSwap = null
    } = {}) {
        return this.authzDiffService.evaluate({
            request: this._buildAuthzDiffRequest(candidate),
            baseline: {
                session: baselineSession || { label: "baseline", relation: "baseline" },
                response: baselineResponse
            },
            comparison: {
                session: comparisonSession || { label: "comparison", relation: "comparison" },
                response: comparisonResponse
            },
            objectSwap
        })
    }

    _deriveAuthzDiffRunState(run = {}) {
        const baselineStatus = normalizeRunStatus(run?.baselineRun?.status || "queued")
        const comparisonStatus = normalizeRunStatus(run?.comparisonRun?.status || "queued")
        const failureRun = [run?.baselineRun, run?.comparisonRun].find((entry) => {
            const status = normalizeRunStatus(entry?.status || "")
            return status === "failed" || status === "canceled" || status === "timed_out"
        }) || null
        if (failureRun) {
            return {
                status: "failed",
                stage: "job_failed",
                error: failureRun?.error || `Playwright job ended with status ${failureRun?.status || "failed"}.`
            }
        }
        if (baselineStatus === "completed" && comparisonStatus === "completed") {
            return {
                status: "running",
                stage: "diffing",
                error: null
            }
        }
        if (baselineStatus === "queued" || comparisonStatus === "queued") {
            return {
                status: "running",
                stage: "queued",
                error: null
            }
        }
        return {
            status: "running",
            stage: "polling_jobs",
            error: null
        }
    }

    async _resolveSessionProfile(sessionProfileId = null) {
        const id = String(sessionProfileId || "").trim()
        if (!id || !this.sessionProfileStore?.getProfile) return null
        const profile = await this.sessionProfileStore.getProfile(id, { includeSnapshot: true })
        if (!profile) return null
        return cloneValue(profile)
    }

    _applyObjectSwapToRequestSeed(requestSeed = null, candidate = null, objectSwap = null) {
        if (!objectSwap || typeof objectSwap !== "object") {
            return {
                requestSeed,
                objectSwap: null
            }
        }
        return this.objectSwapService.apply(requestSeed, candidate, objectSwap)
    }

    _buildBugBountySnapshot() {
        const authzDiffs = this.authzDiffRunStore.list()
            .filter((run) => run?.diff && typeof run.diff === "object")
            .map((run) => ({
                id: run.runId,
                candidateId: run.candidateId || null,
                status: run.status || "completed",
                stage: run.stage || "completed",
                baselineSession: run?.baselineSession?.label || null,
                comparisonSession: run?.comparisonSession?.label || null,
                category: run?.diff?.result?.category || null,
                summary: run?.diff?.result?.summary || null,
                objectSwap: run?.objectSwap || null,
                completedAt: run?.finishedAt || run?.updatedAt || null
            }))
        const evidencePackages = this.evidencePackageStore.list().map((entry) => ({
            id: entry.id,
            candidateId: entry.candidateId || null,
            title: entry.title || null,
            summary: entry.summary || null,
            routeKey: entry.routeKey || null,
            sessions: entry.sessions || null,
            objectSwap: entry.objectSwap || null,
            diffCategory: entry?.diff?.result?.category || null,
            workflowSummary: entry.workflowSummary || null,
            createdAt: entry.createdAt || null
        }))
        const workflowRuns = evidencePackages
            .filter((entry) => entry?.workflowSummary && typeof entry.workflowSummary === "object")
            .map((entry) => ({
                id: `workflow_${entry.id}`,
                label: entry.title || entry.summary || entry.candidateId || "workflow",
                candidateId: entry.candidateId || null,
                stepCount: Number(entry?.workflowSummary?.stepCount || 0),
                source: entry?.workflowSummary?.source || "saved_recording"
            }))
        return {
            authzDiffs,
            evidencePackages,
            workflowRuns
        }
    }

    _notifyBugBountyState() {
        if (!this.onBugBountyStateChanged) return
        try {
            this.onBugBountyStateChanged(this._buildBugBountySnapshot())
        } catch (_) {
            // no-op
        }
    }

    async _resolveWorkflowSummary({ candidate = null, objectSwap = null, baselineSession = null, comparisonSession = null } = {}) {
        if (!this.workflowOverlayService?.getSummary) return null
        try {
            return await this.workflowOverlayService.getSummary({
                candidate,
                objectSwap,
                baselineSession,
                comparisonSession
            })
        } catch (_) {
            return null
        }
    }

    async _buildEvidenceContext({
        candidate = null,
        run = null,
        baselineSession = null,
        comparisonSession = null,
        baselineResponse = null,
        comparisonResponse = null,
        objectSwap = null,
        persist = false,
        title = "",
        notes = ""
    } = {}) {
        const resolvedCandidate = candidate && typeof candidate === "object" ? candidate : null
        if (!resolvedCandidate) throw new Error("candidate_not_found")
        const requestSeed = this._resolveCandidateRequestSeed(resolvedCandidate)
        const swapResolution = this._applyObjectSwapToRequestSeed(requestSeed, resolvedCandidate, objectSwap)
        const appliedObjectSwap = run?.objectSwap || swapResolution?.objectSwap || null
        const resolvedBaselineResponse = baselineResponse || run?.baselineResponse || null
        const resolvedComparisonResponse = comparisonResponse || run?.comparisonResponse || null
        if (!resolvedBaselineResponse || !resolvedComparisonResponse) {
            throw new Error("baseline_and_comparison_responses_required")
        }
        const resolvedBaselineSession = baselineSession || run?.baselineSession || { label: "baseline", relation: "baseline" }
        const resolvedComparisonSession = comparisonSession || run?.comparisonSession || { label: "comparison", relation: "comparison" }
        const diff = run?.diff || this._evaluateAuthzDiff(resolvedCandidate, {
            baselineSession: resolvedBaselineSession,
            comparisonSession: resolvedComparisonSession,
            baselineResponse: resolvedBaselineResponse,
            comparisonResponse: resolvedComparisonResponse,
            objectSwap: appliedObjectSwap
        })
        const workflowSummary = await this._resolveWorkflowSummary({
            candidate: resolvedCandidate,
            objectSwap: appliedObjectSwap,
            baselineSession: resolvedBaselineSession,
            comparisonSession: resolvedComparisonSession
        })
        const reproductionSteps = this.reproductionStepBuilder.build({
            candidate: resolvedCandidate,
            baselineSession: resolvedBaselineSession,
            comparisonSession: resolvedComparisonSession,
            objectSwap: appliedObjectSwap,
            workflowSummary
        })
        const workflowDiff = this.workflowDiffService.diff({
            workflowSummary,
            reproductionSteps
        })
        const evidencePackage = {
            candidateId: resolvedCandidate.id || null,
            title: String(title || resolvedCandidate?.title || "Authz diff evidence").trim(),
            summary: String(notes || diff?.result?.summary || "").trim(),
            routeKey: resolvedCandidate?.routeKey || null,
            sessions: {
                baseline: resolvedBaselineSession,
                comparison: resolvedComparisonSession
            },
            objectSwap: appliedObjectSwap,
            diff,
            request: summarizeRequestSeed(swapResolution?.requestSeed || requestSeed),
            baselineResponse: summarizeComparableResponse(resolvedBaselineResponse),
            comparisonResponse: summarizeComparableResponse(resolvedComparisonResponse),
            workflowSummary: workflowSummary
                ? {
                    ...workflowSummary,
                    diff: workflowDiff
                }
                : null,
            reproductionSteps,
            tags: ["bugbounty", "authz_diff"]
        }
        const persistedEvidencePackage = persist
            ? this.evidencePackageStore.save(evidencePackage)
            : evidencePackage
        const reportDraft = this.reportDraftBuilder.build({
            evidencePackage: persistedEvidencePackage
        })
        if (persist) {
            this._notifyBugBountyState()
        }
        return {
            evidencePackage: persistedEvidencePackage,
            reportDraft,
            workflowSummary: evidencePackage.workflowSummary
        }
    }

    _buildPlaywrightAuthContext({ authMode = "reuse_storage_state", sessionProfile = null } = {}) {
        if (!sessionProfile) {
            return {
                mode: String(authMode || "reuse_storage_state"),
                storageStateRef: "ptk_profile_default"
            }
        }
        return {
            mode: "session_profile",
            sessionProfileId: sessionProfile.id || null,
            sessionProfileLabel: sessionProfile.label || "session",
            cookieSnapshot: Array.isArray(sessionProfile?.snapshot?.cookies)
                ? sessionProfile.snapshot.cookies.map((cookie) => ({
                    name: cookie?.name || "",
                    value: cookie?.value || "",
                    domain: cookie?.domain || "",
                    path: cookie?.path || "/",
                    secure: cookie?.secure === true,
                    httpOnly: cookie?.httpOnly === true,
                    sameSite: cookie?.sameSite || "no_restriction",
                    expirationDate: Number.isFinite(Number(cookie?.expirationDate)) ? Number(cookie.expirationDate) : undefined
                }))
                : []
        }
    }

    _applySessionProfileToRequestSeed(requestSeed = null, sessionProfile = null) {
        if (!requestSeed || !sessionProfile) return requestSeed
        if (Array.isArray(requestSeed?.cookies) && requestSeed.cookies.length) return requestSeed
        const cookieSnapshot = Array.isArray(sessionProfile?.snapshot?.cookies)
            ? sessionProfile.snapshot.cookies
            : []
        if (!cookieSnapshot.length) return requestSeed
        return {
            ...requestSeed,
            cookies: cookieSnapshot.map((cookie) => ({
                name: cookie?.name || "",
                value: cookie?.value || "",
                domain: cookie?.domain || "",
                path: cookie?.path || "/",
                secure: cookie?.secure === true,
                httpOnly: cookie?.httpOnly === true,
                sameSite: cookie?.sameSite || "no_restriction"
            }))
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

    async runCandidateInPlaywright({ candidateId = null, profile = "smoke", authMode = "reuse_storage_state", constraints = {}, sessionProfileId = null } = {}) {
        const id = String(candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found" }
        try {
            const readiness = await this.computeReadiness(candidate, { skipNetwork: false })
            if (readiness?.runInPlaywright === "blocked") {
                return { success: false, candidateId: id, error: "candidate_not_ready_for_playwright_run", readiness }
            }
            const sessionProfile = await this._resolveSessionProfile(sessionProfileId)
            if (sessionProfileId && !sessionProfile) {
                return { success: false, candidateId: id, error: "session_profile_not_found" }
            }
            const run = await this._startCandidatePlaywrightRun({
                candidateId: id,
                candidate,
                profile,
                authMode,
                constraints,
                sessionProfile,
                persist: true,
                sessionRelation: "active"
            })
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

    async compareCandidateAuthzDiff({
        candidateId = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null,
        baselineResponse = null,
        comparisonResponse = null,
        objectSwap = null
    } = {}) {
        const id = String(candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found", candidateId: id }
        if (!baselineResponse || !comparisonResponse) {
            return { success: false, error: "baseline_and_comparison_responses_required", candidateId: id }
        }
        const baselineProfile = baselineSessionProfileId
            ? await this._resolveSessionProfile(baselineSessionProfileId)
            : null
        if (baselineSessionProfileId && !baselineProfile) {
            return { success: false, error: "baseline_session_profile_not_found", candidateId: id }
        }
        const comparisonProfile = comparisonSessionProfileId
            ? await this._resolveSessionProfile(comparisonSessionProfileId)
            : null
        if (comparisonSessionProfileId && !comparisonProfile) {
            return { success: false, error: "comparison_session_profile_not_found", candidateId: id }
        }
        const diff = this._evaluateAuthzDiff(candidate, {
            baselineSession: normalizeSessionProfileSummary(baselineProfile, "baseline") || { label: "baseline", relation: "baseline" },
            comparisonSession: normalizeSessionProfileSummary(comparisonProfile, "comparison") || { label: "comparison", relation: "comparison" },
            baselineResponse,
            comparisonResponse,
            objectSwap
        })
        return {
            success: true,
            candidateId: id,
            diff
        }
    }

    async suggestCandidateObjectSwap({
        candidateId = null,
        objectSwap = null
    } = {}) {
        const id = String(candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found", candidateId: id }
        const requestSeed = this._resolveCandidateRequestSeed(candidate)
        if (!requestSeed) {
            return { success: false, error: "candidate_request_seed_unavailable", candidateId: id }
        }
        const suggestion = this.objectSwapService.suggest({
            candidate,
            requestSeed,
            objectSwap
        })
        return {
            success: true,
            candidateId: id,
            objectSwap: suggestion
        }
    }

    async runCandidateAuthzDiff({
        candidateId = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null,
        profile = "smoke",
        constraints = {},
        objectSwap = null
    } = {}) {
        const id = String(candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        if (!baselineSessionProfileId || !comparisonSessionProfileId) {
            return { success: false, error: "baseline_and_comparison_sessions_required", candidateId: id }
        }
        if (String(baselineSessionProfileId) === String(comparisonSessionProfileId)) {
            return { success: false, error: "baseline_and_comparison_sessions_must_differ", candidateId: id }
        }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found", candidateId: id }
        try {
            const readiness = await this.computeReadiness(candidate, { skipNetwork: false })
            if (readiness?.runInPlaywright === "blocked") {
                return { success: false, candidateId: id, error: "candidate_not_ready_for_playwright_run", readiness }
            }
            const [baselineProfile, comparisonProfile] = await Promise.all([
                this._resolveSessionProfile(baselineSessionProfileId),
                this._resolveSessionProfile(comparisonSessionProfileId)
            ])
            if (!baselineProfile) {
                return { success: false, error: "baseline_session_profile_not_found", candidateId: id }
            }
            if (!comparisonProfile) {
                return { success: false, error: "comparison_session_profile_not_found", candidateId: id }
            }
            const runId = buildAuthzDiffRunId()
            this.authzDiffRunStore.upsert(runId, {
                candidateId: id,
                status: "queued",
                stage: "starting",
                baselineSession: normalizeSessionProfileSummary(baselineProfile, "baseline"),
                comparisonSession: normalizeSessionProfileSummary(comparisonProfile, "comparison"),
                objectSwap: objectSwap || null
            })
            const [baselineRun, comparisonRun] = await Promise.all([
                this._startCandidatePlaywrightRun({
                    candidateId: id,
                    candidate,
                    profile,
                    authMode: "session_profile",
                    constraints,
                    sessionProfile: baselineProfile,
                    objectSwap,
                    persist: false,
                    sessionRelation: "baseline"
                }),
                this._startCandidatePlaywrightRun({
                    candidateId: id,
                    candidate,
                    profile,
                    authMode: "session_profile",
                    constraints,
                    sessionProfile: comparisonProfile,
                    objectSwap,
                    persist: false,
                    sessionRelation: "comparison"
                })
            ])
            const run = this.authzDiffRunStore.upsert(runId, {
                candidateId: id,
                status: "running",
                stage: "queued",
                baselineSession: normalizeSessionProfileSummary(baselineProfile, "baseline"),
                comparisonSession: normalizeSessionProfileSummary(comparisonProfile, "comparison"),
                objectSwap: baselineRun?.objectSwap || comparisonRun?.objectSwap || objectSwap || null,
                baselineRun,
                comparisonRun
            })
            return {
                success: true,
                candidateId: id,
                run,
                readiness
            }
        } catch (err) {
            return {
                success: false,
                candidateId: id,
                error: err?.message || "authz_diff_run_failed_to_start"
            }
        }
    }

    async getCandidateAuthzDiffRun({ runId = null } = {}) {
        const id = String(runId || "").trim()
        if (!id) return { success: false, error: "authz_diff_run_id_required" }
        const existing = this.authzDiffRunStore.get(id)
        if (!existing) return { success: false, error: "authz_diff_run_not_found", runId: id }
        if (isTerminalRunStatus(existing?.status)) {
            return { success: true, runId: id, run: existing }
        }
        const candidateId = String(existing?.candidateId || "").trim()
        const candidate = this.getCandidate?.(candidateId)
        if (!candidate) {
            const failed = this.authzDiffRunStore.upsert(id, {
                status: "failed",
                stage: "job_failed",
                error: "candidate_not_found"
            })
            return { success: true, runId: id, run: failed }
        }
        let baselineRun = existing?.baselineRun || null
        let comparisonRun = existing?.comparisonRun || null
        try {
            if (baselineRun && !isTerminalRunStatus(baselineRun?.status)) {
                baselineRun = await this._pollPlaywrightJobRun(baselineRun, candidateId)
            }
            if (comparisonRun && !isTerminalRunStatus(comparisonRun?.status)) {
                comparisonRun = await this._pollPlaywrightJobRun(comparisonRun, candidateId)
            }
        } catch (err) {
            const failed = this.authzDiffRunStore.upsert(id, {
                status: "failed",
                stage: "job_failed",
                error: err?.message || "playwright_mcp_poll_failed",
                baselineRun,
                comparisonRun
            })
            return { success: true, runId: id, run: failed }
        }

        const derived = this._deriveAuthzDiffRunState({
            ...existing,
            baselineRun,
            comparisonRun
        })
        let next = this.authzDiffRunStore.upsert(id, {
            status: derived.status,
            stage: derived.stage,
            error: derived.error,
            baselineRun,
            comparisonRun
        })

        if (derived.status === "failed") {
            return { success: true, runId: id, run: next }
        }

        if (derived.stage === "diffing") {
            const baselineResponse = extractComparableResponseFromRun(baselineRun)
            const comparisonResponse = extractComparableResponseFromRun(comparisonRun)
            const appliedObjectSwap = next?.objectSwap?.applied === true
                ? next.objectSwap
                : (baselineRun?.objectSwap?.applied === true
                    ? baselineRun.objectSwap
                    : (comparisonRun?.objectSwap?.applied === true ? comparisonRun.objectSwap : (next?.objectSwap || null)))
            if (!baselineResponse || !comparisonResponse) {
                next = this.authzDiffRunStore.upsert(id, {
                    status: "failed",
                    stage: "job_failed",
                    error: "Playwright authz diff runs completed but no comparable response artifact was captured.",
                    baselineRun: {
                        ...baselineRun,
                        comparableResponse: baselineResponse
                    },
                    comparisonRun: {
                        ...comparisonRun,
                        comparableResponse: comparisonResponse
                    }
                })
                return { success: true, runId: id, run: next }
            }
            const diff = this._evaluateAuthzDiff(candidate, {
                baselineSession: next?.baselineSession || normalizeSessionProfileSummary(null, "baseline") || { label: "baseline", relation: "baseline" },
                comparisonSession: next?.comparisonSession || normalizeSessionProfileSummary(null, "comparison") || { label: "comparison", relation: "comparison" },
                baselineResponse,
                comparisonResponse,
                objectSwap: appliedObjectSwap
            })
            next = this.authzDiffRunStore.upsert(id, {
                status: "completed",
                stage: "completed",
                error: null,
                baselineRun: {
                    ...baselineRun,
                    comparableResponse: baselineResponse
                },
                comparisonRun: {
                    ...comparisonRun,
                    comparableResponse: comparisonResponse
                },
                baselineResponse,
                comparisonResponse,
                objectSwap: appliedObjectSwap,
                diff
            })
            this._notifyBugBountyState()
        }

        return { success: true, runId: id, run: next }
    }

    async createEvidencePackageFromAuthzDiff({
        candidateId = null,
        runId = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null,
        baselineResponse = null,
        comparisonResponse = null,
        objectSwap = null,
        title = "",
        notes = ""
    } = {}) {
        const resolvedCandidateId = String(candidateId || "").trim()
        const resolvedRunId = String(runId || "").trim()
        const run = resolvedRunId ? this.authzDiffRunStore.get(resolvedRunId) : null
        const id = resolvedCandidateId || String(run?.candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found", candidateId: id }

        const baselineProfile = run?.baselineSession?.id
            ? null
            : (baselineSessionProfileId ? await this._resolveSessionProfile(baselineSessionProfileId) : null)
        const comparisonProfile = run?.comparisonSession?.id
            ? null
            : (comparisonSessionProfileId ? await this._resolveSessionProfile(comparisonSessionProfileId) : null)

        const resolvedBaselineSession = run?.baselineSession
            || normalizeSessionProfileSummary(baselineProfile, "baseline")
            || { label: "baseline", relation: "baseline" }
        const resolvedComparisonSession = run?.comparisonSession
            || normalizeSessionProfileSummary(comparisonProfile, "comparison")
            || { label: "comparison", relation: "comparison" }

        try {
            const { evidencePackage, reportDraft, workflowSummary } = await this._buildEvidenceContext({
                candidate,
                run,
                baselineSession: resolvedBaselineSession,
                comparisonSession: resolvedComparisonSession,
                baselineResponse,
                comparisonResponse,
                objectSwap: objectSwap || run?.objectSwap || null,
                persist: true,
                title,
                notes
            })
            return {
                success: true,
                candidateId: id,
                runId: resolvedRunId || null,
                evidencePackage,
                reportDraft,
                workflowSummary
            }
        } catch (err) {
            return {
                success: false,
                candidateId: id,
                error: err?.message || "evidence_package_failed"
            }
        }
    }

    async listEvidencePackages({
        candidateId = null
    } = {}) {
        const id = String(candidateId || "").trim()
        const evidencePackages = this.evidencePackageStore.list({ candidateId: id || null })
            .map((entry) => ({
                id: entry.id,
                createdAt: entry.createdAt || null,
                updatedAt: entry.updatedAt || null,
                candidateId: entry.candidateId || null,
                title: entry.title || null,
                summary: entry.summary || entry?.diff?.result?.summary || null,
                routeKey: entry.routeKey || null,
                sessions: entry.sessions || null,
                objectSwap: entry.objectSwap || null,
                diffCategory: entry?.diff?.result?.category || null,
                workflowSummary: entry.workflowSummary || null,
                reproductionStepCount: Array.isArray(entry?.reproductionSteps) ? entry.reproductionSteps.length : 0
            }))
        return {
            success: true,
            candidateId: id || null,
            evidencePackages
        }
    }

    async getEvidencePackage({
        evidencePackageId = null
    } = {}) {
        const id = String(evidencePackageId || "").trim()
        if (!id) return { success: false, error: "evidence_package_id_required" }
        const evidencePackage = this.evidencePackageStore.get(id)
        if (!evidencePackage) {
            return {
                success: false,
                error: "evidence_package_not_found",
                evidencePackageId: id
            }
        }
        return {
            success: true,
            evidencePackageId: id,
            evidencePackage,
            reportDraft: this.reportDraftBuilder.build({ evidencePackage })
        }
    }

    async exportEvidencePackage({
        evidencePackageId = null,
        format = "json"
    } = {}) {
        const resolvedId = String(evidencePackageId || "").trim()
        if (!resolvedId) return { success: false, error: "evidence_package_id_required" }
        const evidencePackage = this.evidencePackageStore.get(resolvedId)
        if (!evidencePackage) {
            return {
                success: false,
                error: "evidence_package_not_found",
                evidencePackageId: resolvedId
            }
        }
        const reportDraft = this.reportDraftBuilder.build({ evidencePackage })
        const normalizedFormat = String(format || "json").trim().toLowerCase()
        const baseName = sanitizeEvidenceFilename(evidencePackage?.title || evidencePackage?.routeKey || resolvedId)
        if (normalizedFormat === "markdown" || normalizedFormat === "md") {
            return {
                success: true,
                evidencePackageId: resolvedId,
                format: "markdown",
                fileName: `${baseName}.md`,
                contentType: "text/markdown",
                content: String(reportDraft?.markdown || "").trim()
            }
        }
        return {
            success: true,
            evidencePackageId: resolvedId,
            format: "json",
            fileName: `${baseName}.json`,
            contentType: "application/json",
            content: JSON.stringify({
                evidencePackage,
                reportDraft
            }, null, 2)
        }
    }

    async buildCandidateReportDraft({
        candidateId = null,
        runId = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null,
        baselineResponse = null,
        comparisonResponse = null,
        objectSwap = null,
        title = "",
        notes = ""
    } = {}) {
        const resolvedCandidateId = String(candidateId || "").trim()
        const resolvedRunId = String(runId || "").trim()
        const run = resolvedRunId ? this.authzDiffRunStore.get(resolvedRunId) : null
        const id = resolvedCandidateId || String(run?.candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found", candidateId: id }
        const baselineProfile = baselineSessionProfileId ? await this._resolveSessionProfile(baselineSessionProfileId) : null
        const comparisonProfile = comparisonSessionProfileId ? await this._resolveSessionProfile(comparisonSessionProfileId) : null
        try {
            const { evidencePackage, reportDraft, workflowSummary } = await this._buildEvidenceContext({
                candidate,
                run,
                baselineSession: run?.baselineSession || normalizeSessionProfileSummary(baselineProfile, "baseline"),
                comparisonSession: run?.comparisonSession || normalizeSessionProfileSummary(comparisonProfile, "comparison"),
                baselineResponse,
                comparisonResponse,
                objectSwap: objectSwap || run?.objectSwap || null,
                persist: false,
                title,
                notes
            })
            return {
                success: true,
                candidateId: id,
                evidencePreview: evidencePackage,
                reportDraft,
                workflowSummary
            }
        } catch (err) {
            return {
                success: false,
                candidateId: id,
                error: err?.message || "report_draft_failed"
            }
        }
    }

    async getWorkflowOverlaySummary({
        candidateId = null,
        objectSwap = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null
    } = {}) {
        const id = String(candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found", candidateId: id }
        const [baselineProfile, comparisonProfile] = await Promise.all([
            baselineSessionProfileId ? this._resolveSessionProfile(baselineSessionProfileId) : null,
            comparisonSessionProfileId ? this._resolveSessionProfile(comparisonSessionProfileId) : null
        ])
        const workflowSummary = await this._resolveWorkflowSummary({
            candidate,
            objectSwap,
            baselineSession: normalizeSessionProfileSummary(baselineProfile, "baseline"),
            comparisonSession: normalizeSessionProfileSummary(comparisonProfile, "comparison")
        })
        return {
            success: true,
            candidateId: id,
            workflowSummary
        }
    }

    async startWorkflowOverlayReplay({
        candidateId = null,
        objectSwap = null,
        baselineSessionProfileId = null,
        comparisonSessionProfileId = null,
        replaySessionRelation = "comparison",
        cleanCookie = true,
        includeDestructive = false,
        validateRegex = null
    } = {}) {
        const id = String(candidateId || "").trim()
        if (!id) return { success: false, error: "candidate_id_required" }
        const candidate = this.getCandidate?.(id)
        if (!candidate) return { success: false, error: "candidate_not_found", candidateId: id }
        if (!this.workflowOverlayService?.buildReplayPlan) {
            return { success: false, error: "workflow_overlay_unavailable", candidateId: id }
        }
        if (!this.startWorkflowReplay) {
            return { success: false, error: "workflow_replay_unavailable", candidateId: id }
        }

        const relation = String(replaySessionRelation || "comparison").trim().toLowerCase() === "baseline"
            ? "baseline"
            : "comparison"
        const [baselineProfile, comparisonProfile] = await Promise.all([
            baselineSessionProfileId ? this._resolveSessionProfile(baselineSessionProfileId) : null,
            comparisonSessionProfileId ? this._resolveSessionProfile(comparisonSessionProfileId) : null
        ])
        const baselineSession = normalizeSessionProfileSummary(baselineProfile, "baseline")
            || { label: "baseline", relation: "baseline" }
        const comparisonSession = normalizeSessionProfileSummary(comparisonProfile, "comparison")
            || { label: "comparison", relation: "comparison" }
        const activeSessionProfile = relation === "baseline" ? baselineProfile : comparisonProfile
        const activeSession = relation === "baseline" ? baselineSession : comparisonSession

        try {
            const replayPlan = await this.workflowOverlayService.buildReplayPlan({
                candidate,
                objectSwap,
                baselineSession,
                comparisonSession,
                activeSession,
                activeSessionProfile,
                sessionRelation: relation,
                includeDestructive
            })
            if (!replayPlan?.recordingPresent || !Array.isArray(replayPlan?.items) || !replayPlan.items.length) {
                return {
                    success: false,
                    error: "workflow_recording_unavailable",
                    candidateId: id
                }
            }
            const startResponse = await this.startWorkflowReplay({
                clean_cookie: cleanCookie === true,
                url: replayPlan.startUrl,
                events: replayPlan.items,
                validate_regex: validateRegex || null,
                overlay: replayPlan.overlayPlan,
                session_profile: activeSessionProfile
                    ? {
                        id: activeSessionProfile.id || null,
                        label: activeSessionProfile.label || null,
                        host: activeSessionProfile.host || null,
                        snapshot: activeSessionProfile.snapshot || null
                    }
                    : null
            })
            if (startResponse?.success === false) {
                return {
                    success: false,
                    error: startResponse?.error || "workflow_replay_start_failed",
                    candidateId: id,
                    workflowSummary: replayPlan.overlayPlan?.workflowSummary || null
                }
            }
            return {
                success: true,
                candidateId: id,
                workflowSummary: replayPlan.overlayPlan?.workflowSummary || null,
                replayPlan: {
                    summary: {
                        recordingPresent: replayPlan.recordingPresent === true,
                        source: replayPlan.source || "none",
                        stepCount: Number(replayPlan.stepCount || 0),
                        overlayedStepCount: Number(replayPlan.overlayedStepCount || 0),
                        skippedStepCount: Number(replayPlan.skippedStepCount || 0),
                        activeSessionLabel: replayPlan.activeSessionLabel || activeSession?.label || null,
                        startUrl: replayPlan.startUrl || null
                    },
                    overlay: replayPlan.overlayPlan || null
                }
            }
        } catch (err) {
            return {
                success: false,
                error: err?.message || "workflow_replay_failed",
                candidateId: id
            }
        }
    }
}

export default DastCandidateRunService
